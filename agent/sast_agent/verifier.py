"""Adversarial review (AGENT_MVP_PLAN.md §7, milestone M4).

For every finding the investigator judged vulnerable, two INDEPENDENT
rounds run on fresh agent instances. Each sees the evidence package (sink,
chain, evidence refs, verdict) but not the investigator's message history:

- **attacker**: construct a concrete trigger HTTP request (method, path,
  parameters, payload) and walk the data hop by hop to the sink. Failure
  to construct -> downgrade (applied in report.apply_verifier).
- **defender**: hunt for an effective sanitizer / auth gate / type
  constraint on the path, with concrete file:line refs. An effective,
  resolvable sanitizer -> veto (verdict flips to not vulnerable).

Both roles may use read_function / search_code (ground-truth files
refused by the tool layer; VULN:/SAFE: tag comments stripped here) but
NOT joern_query (§7). This module only produces the two reports — the
mechanical merge into verdict + confidence_level (plan §4) lives in
report.apply_verifier, so a verifier failure (timeout/quota) never
changes a verdict by itself.

Reports come back via a submit_report tool call (extracted from the
message history), NOT output_type: the DeepSeek thinking-mode endpoint
rejects the tool_choice that pydantic-ai's structured output emits
("Thinking mode does not support this tool_choice") — the same reason
investigator.py submits via submit_finding.

Usage:
    from sast_agent.verifier import verify_finding
    vres = await verify_finding(finding, tools, token_budget=50_000)
"""

import asyncio

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext, UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ToolCallPart
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from . import config
from .contracts import BFinding, Finding
from .investigator import _strip_gt_tags
from .tools import SastTools


class AttackerReport(BaseModel):
    """Attacker round output: can a concrete trigger be constructed?"""

    exploit_possible: bool
    request: str | None = None  # concrete trigger HTTP request incl. payload
    reasoning: str              # hop-by-hop path, or why it fails


class DefenderReport(BaseModel):
    """Defender round output: is there effective mitigation on the path?"""

    effective_sanitizer: bool
    kind: str | None = None     # parameterized query | escaping | allowlist |
                                # auth gate | type constraint | parser option
    refs: list[str] = Field(default_factory=list)  # file:start-end the claim rests on
    reasoning: str


_ATTACKER_PROMPT = """\
You are a senior application-security engineer acting as the ATTACKER in an
adversarial review. Another analyst judged the suspected vulnerability below
VULNERABLE. Your job is to prove exploitability by constructing a concrete
trigger.

Produce a specific HTTP request (method, path, parameters, payload) that
carries attacker-controlled data to the sink's dangerous argument, and
explain each hop from the request to the sink. Use read_function /
search_code to confirm route paths, parameter names and the exact sink
call before you claim them.

Rules:
- Every hop must be backed by the evidence below or by code you actually
  read — if you cannot substantiate a hop, set exploit_possible=false and
  say which hop is unproven.
- If sanitization on the path neutralizes your payload (parameterized
  API, escaping, allow-list, disabled parser feature), set
  exploit_possible=false and name the mitigation.
- Keep the payload minimal and realistic for the vulnerability class.
- Finish by calling submit_report exactly once. This is mandatory."""

_DEFENDER_PROMPT = """\
You are a senior application-security engineer acting as the DEFENDER in an
adversarial review. Another analyst judged the suspected vulnerability below
VULNERABLE. Your job is to disprove it.

Look for EFFECTIVE sanitization or mitigation on the path from the HTTP
entrypoint to the sink:
- parameterized queries / prepared statements instead of string building
- output encoding/escaping at the sink
- allow-list validation or strict type coercion of the tainted input
- parser options disabling dangerous features (e.g. XML entity resolution
  disabled via noent:false / resolve_entities=False)
- authentication/authorization gates that make the sink unreachable for an
  attacker
- a hardened wrapper / safe API variant at the sink call itself

Rules:
- Use read_function and search_code to inspect the real code — do not
  rely on the investigator's summary alone.
- Report effective_sanitizer=true ONLY when you can point at concrete
  code: put its "file:start-end" refs in refs and name the kind. A
  superficial, bypassable or unrelated check does NOT count.
- If a mitigation only reduces impact but attacker-controlled data still
  reaches the dangerous argument, report effective_sanitizer=false.
- When in doubt, report effective_sanitizer=false — a false veto hides a
  real vulnerability.
- Finish by calling submit_report exactly once. This is mandatory."""


def _context(finding: Finding) -> str:
    """The shared evidence package both roles see (no message history)."""
    sink = finding.sink
    lines = [
        f"Suspected {sink.vuln_type} vulnerability.",
        f"Sink: `{sink.name}` at {sink.file}:{sink.line} "
        f"(semgrep rule {sink.rule})",
    ]
    if finding.chain:
        c = finding.chain
        lines.append(f"Call chain: route {c.route or '?'}, "
                     f"entrypoint `{c.entrypoint}`")
        if c.path:
            lines.append("Chain path: " + " -> ".join(c.path))
    else:
        lines.append("Call chain: (none — investigator drilled manually)")
    lines.append(f"Investigator verdict: VULNERABLE "
                 f"(confidence {finding.verdict.confidence:.2f})")
    lines.append(f"Investigator reasoning: {finding.verdict.reasoning}")
    if finding.evidence:
        lines.append("Evidence collected:")
        for e in finding.evidence:
            refs = ", ".join(e.refs) if e.refs else "no refs"
            lines.append(f"- [{e.kind}] {e.summary} (refs: {refs})")
    if finding.exploit_sketch:
        lines.append(f"Investigator exploit sketch: {finding.exploit_sketch}")
    if finding.sanitizer_notes:
        lines.append(f"Investigator sanitizer notes: {finding.sanitizer_notes}")
    return "\n".join(lines)


def _model() -> OpenAIChatModel:
    return OpenAIChatModel(config.MODEL, provider=OpenAIProvider(
        base_url=config.BASE_URL, api_key=config.API_KEY))


def _add_read_tools(agent: Agent) -> None:
    """read/search only — no joern_query (§7); ground-truth tags stripped
    from tool output (red line §9.2, same as the judge snippet checks)."""

    @agent.tool
    def read_function(ctx: RunContext[SastTools], file: str,
                      start: int, end: int) -> str:
        """Read lines start..end (1-based, inclusive) of a source file in
        the target tree, with line numbers."""
        return _strip_gt_tags(ctx.deps.read_function(file, start, end))

    @agent.tool
    def search_code(ctx: RunContext[SastTools], pattern: str,
                    glob: str | None = None) -> str:
        """Regex search across the target tree (ripgrep, ±2 lines of
        context)."""
        return _strip_gt_tags(ctx.deps.search_code(pattern, glob))


def _build_attacker() -> Agent:
    agent = Agent(_model(), deps_type=SastTools,
                  instructions=_ATTACKER_PROMPT, retries=2)
    _add_read_tools(agent)

    @agent.tool
    def submit_report(ctx: RunContext[SastTools], report: AttackerReport) -> dict:
        """Submit the final attacker report. Call exactly once, last."""
        return {"ok": True}

    return agent


def _build_defender() -> Agent:
    agent = Agent(_model(), deps_type=SastTools,
                  instructions=_DEFENDER_PROMPT, retries=2)
    _add_read_tools(agent)

    @agent.tool
    def submit_report(ctx: RunContext[SastTools], report: DefenderReport) -> dict:
        """Submit the final defender report. Call exactly once, last."""
        return {"ok": True}

    return agent


def _extract_report(messages, model):
    """The report submitted via the submit_report tool call (latest valid
    one wins) — same extraction pattern as investigator._extract_submission."""
    for msg in reversed(messages):
        for part in getattr(msg, "parts", []):
            if isinstance(part, ToolCallPart) and part.tool_name == "submit_report":
                try:
                    args = part.args_as_dict()
                    return model.model_validate(args.get("report", args))
                except Exception:
                    continue
    return None


async def _run_one(agent: Agent, model, prompt: str, tools: SastTools,
                   token_budget: int):
    """One verifier round. Returns (report|None, tokens, status) — a
    failure returns None so the merge layer can ignore the round."""
    try:
        result = await asyncio.wait_for(
            agent.run(
                prompt,
                deps=tools,
                usage_limits=UsageLimits(
                    request_limit=config.VERIFIER_MAX_TOOL_CALLS + 2,
                    total_tokens_limit=max(token_budget, 1),
                ),
            ),
            timeout=config.VERIFIER_TIMEOUT_SECONDS,
        )
        usage = result.usage
        tokens = usage.total_tokens or (
            (usage.input_tokens or 0) + (usage.output_tokens or 0))
        report = _extract_report(result.all_messages(), model)
        return report, tokens, "ok" if report is not None else "no_submission"
    except UsageLimitExceeded:
        return None, 0, "budget_exhausted"
    except asyncio.TimeoutError:
        return None, 0, "timeout"
    except Exception as e:
        return None, 0, f"error: {type(e).__name__}: {e}"


async def verify_finding(finding: Finding, tools: SastTools,
                         token_budget: int) -> dict:
    """Run the attacker + defender rounds for one vulnerable finding.

    Returns {"attacker": dict|None, "defender": dict|None, "tokens": int,
    "status": {"attacker": str, "defender": str}} — None rounds are failed
    rounds; report.apply_verifier only acts on rounds that produced a
    report."""
    ctx = _context(finding)
    half = max(token_budget // 2, 1)
    (att, att_tok, att_st), (dfn, dfn_tok, dfn_st) = await asyncio.gather(
        _run_one(_build_attacker(), AttackerReport,
                 ctx + "\n\nConstruct the trigger (or explain why it fails), "
                       "then call submit_report.",
                 tools, half),
        _run_one(_build_defender(), DefenderReport,
                 ctx + "\n\nHunt for an effective sanitizer (or confirm there "
                       "is none), then call submit_report.",
                 tools, half),
    )
    return {
        "attacker": att.model_dump() if att else None,
        "defender": dfn.model_dump() if dfn else None,
        "tokens": att_tok + dfn_tok,
        "status": {"attacker": att_st, "defender": dfn_st},
    }


# ---------------------------------------------------------------------------
# Category-B rounds (§7A, M7): same two-round machinery, but the flaw is an
# ABSENT check — the attacker constructs a concrete over-reach request, the
# defender hunts middleware/framework-level guards mounted outside the
# handler (the worker's forward slice cannot see them).
# ---------------------------------------------------------------------------

_ATTACKER_B_PROMPT = """\
You are a senior application-security engineer acting as the ATTACKER in an
adversarial review. Another analyst judged the suspected category-B
vulnerability below VULNERABLE — a check that SHOULD exist is missing from
the handler. Your job is to prove exploitability by constructing a concrete
over-reach request.

Produce a specific HTTP request that exploits the missing check — e.g. for
idor "as user 1, GET /users/2"; for priv-esc a request that smuggles a
role/admin field; for race-condition the interleaving to fire; for
mass-assignment the body fields beyond the intended set — and explain each
step: which parameter/body field carries the attack, why the missing check
lets it through, what invariant is violated. Use read_function /
search_code to confirm route paths, parameter names and session handling
before you claim them.

Rules:
- Every step must be backed by the evidence below or by code you actually
  read — if you cannot substantiate a step, set exploit_possible=false and
  say which step is unproven.
- If a check on the path actually neutralizes the over-reach (an ownership
  filter, a server-side role source, an allow-list, a lock), set
  exploit_possible=false and name the check.
- Keep the request minimal and realistic for the vulnerability class.
- Finish by calling submit_report exactly once. This is mandatory."""

_DEFENDER_B_PROMPT = """\
You are a senior application-security engineer acting as the DEFENDER in an
adversarial review. Another analyst judged the suspected category-B
vulnerability below VULNERABLE — a check that SHOULD exist is reportedly
missing from the handler. Your job is to disprove it.

The check may live OUTSIDE the handler — the investigator only saw the
handler and its callees. Hunt for guards mounted at the framework level:
- Flask: before_request handlers, blueprint registration with guards,
  decorators applied at import time
- Express: app.use(...) middleware chains
- Spring: filters, interceptors, SecurityConfig / @PreAuthorize defaults
- ASP.NET: middleware pipeline, authorization policies, [Authorize] on a
  base controller
- JSP/legacy: web.xml filters, servlet config
Also re-check the handler itself for the check (ownership filter, role
check, field allow-list, lock/atomic op, server-side invariant).

Rules:
- Use read_function and search_code to inspect the real code — do not
  rely on the investigator's summary alone.
- Report effective_sanitizer=true ONLY when you can point at concrete
  code: put its "file:start-end" refs in refs and name the kind. A
  superficial, bypassable or unrelated check does NOT count.
- If a guard only reduces impact but the over-reach still succeeds,
  report effective_sanitizer=false.
- When in doubt, report effective_sanitizer=false — a false veto hides a
  real vulnerability.
- Finish by calling submit_report exactly once. This is mandatory."""


def _context_b(finding: BFinding) -> str:
    """The shared evidence package both B-class roles see (no message
    history), built from the hypothesis instead of a sink."""
    hyp = finding.hypothesis
    lines = [
        f"Suspected {hyp.vuln_type} at {hyp.route}, "
        f"handler {hyp.entrypoint}.",
        f"Trigger features (planner): {hyp.trigger_features}",
        f"Planner rationale: {hyp.rationale}",
        f"Investigator verdict: VULNERABLE "
        f"(confidence {finding.verdict.confidence:.2f})",
        f"Investigator reasoning: {finding.verdict.reasoning}",
    ]
    if finding.comparison:
        lines.append(f"Absence comparison: {finding.comparison}")
    if finding.evidence:
        lines.append("Evidence collected:")
        for e in finding.evidence:
            refs = ", ".join(e.refs) if e.refs else "no refs"
            lines.append(f"- [{e.kind}] {e.summary} (refs: {refs})")
    if finding.exploit_sketch:
        lines.append(f"Investigator exploit sketch: {finding.exploit_sketch}")
    if finding.sanitizer_notes:
        lines.append(f"Investigator sanitizer notes: {finding.sanitizer_notes}")
    return "\n".join(lines)


def _build_attacker_b() -> Agent:
    agent = Agent(_model(), deps_type=SastTools,
                  instructions=_ATTACKER_B_PROMPT, retries=2)
    _add_read_tools(agent)

    @agent.tool
    def submit_report(ctx: RunContext[SastTools], report: AttackerReport) -> dict:
        """Submit the final attacker report. Call exactly once, last."""
        return {"ok": True}

    return agent


def _build_defender_b() -> Agent:
    agent = Agent(_model(), deps_type=SastTools,
                  instructions=_DEFENDER_B_PROMPT, retries=2)
    _add_read_tools(agent)

    @agent.tool
    def submit_report(ctx: RunContext[SastTools], report: DefenderReport) -> dict:
        """Submit the final defender report. Call exactly once, last."""
        return {"ok": True}

    return agent


async def verify_b_finding(finding: BFinding, tools: SastTools,
                           token_budget: int) -> dict:
    """Run the attacker + defender rounds for one vulnerable category-B
    finding. Same return shape as verify_finding; the mechanical merge
    lives in report.apply_verifier_b."""
    ctx = _context_b(finding)
    half = max(token_budget // 2, 1)
    (att, att_tok, att_st), (dfn, dfn_tok, dfn_st) = await asyncio.gather(
        _run_one(_build_attacker_b(), AttackerReport,
                 ctx + "\n\nConstruct the over-reach request (or explain "
                       "why it fails), then call submit_report.",
                 tools, half),
        _run_one(_build_defender_b(), DefenderReport,
                 ctx + "\n\nHunt for a middleware/framework-level guard (or "
                       "confirm there is none), then call submit_report.",
                 tools, half),
    )
    return {
        "attacker": att.model_dump() if att else None,
        "defender": dfn.model_dump() if dfn else None,
        "tokens": att_tok + dfn_tok,
        "status": {"attacker": att_st, "defender": dfn_st},
    }
