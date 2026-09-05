"""Per-hypothesis category-B worker agent (AGENT_MVP_PLAN.md §7A, M7).

Clones the investigator.py skeleton (build_agent + _ToolGuard call
counting/logging + asyncio.wait_for timeout + UsageLimits + ToolCallPart
submission extraction + honest synthesized fallback), but the evidence
shape is different: a B-class finding proves an ABSENT check, not a
dangerous call. The playbook is the absence-comparison method (§7A
lines 333-346):

1. get_forward_slice(entrypoint) — handler + all downstream callees;
2. look for the check that SHOULD exist for the hypothesis's class;
3. not found -> search_code repo-wide for the idiom used elsewhere;
4. verdict by comparison (sibling has it, this route doesn't ->
   absence established; nobody has it -> check app init / middleware;
   check present -> not vulnerable).

Tools mounted: get_forward_slice + GT-stripped read_function /
search_code wrappers + submit_b_finding. No joern_query: B-class is an
absence proof, CPG queries add little (§7A playbook doesn't use joern).

Confidence mapping (plan §4, mechanical — never LLM-filled) starts in
report.assign_confidence_level_b and is refined by the verifier merge
(report.apply_verifier_b).

Usage:
    from sast_agent.worker import investigate_hypothesis
    finding = await investigate_hypothesis(hyp, tools, token_budget=100_000)
"""

import asyncio
import json
import re
import time

from pydantic import BaseModel
from pydantic_ai import Agent, RunContext, UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ToolCallPart
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from . import config
from .contracts import BFinding, Evidence, Hypothesis, Verdict
from .investigator import _strip_gt_tags
from .report import assign_confidence_level_b
from .tools import SastTools


class BFindingSubmission(BaseModel):
    """What the worker submits via submit_b_finding. confidence_level and
    stats are filled in by the worker (report.py mapping), never by the
    LLM; the hypothesis is echoed back by the worker itself."""

    verdict: Verdict
    evidence: list[Evidence]
    exploit_sketch: str | None = None
    sanitizer_notes: str | None = None
    comparison: str | None = None


# Per-class "should-be check" hints (§7A 假设表) — written into the prompt.
_SHOULD_BE_CHECKS = """\
The check that SHOULD exist, per class:
- idor: an ownership/tenancy check on the fetched object
  (current_user.id == obj.owner_id, a session-scoped query filter)
- broken-access-control: the role/permission check or auth decorator the
  sibling routes carry (login_required, requireRole, [Authorize], filters)
- priv-esc: role/privilege derived server-side from the session, never
  from request data (no role/is_admin taken from body, params or cookies)
- mass-assignment: an explicit field allow-list / DTO / Form model
  instead of binding the whole request body onto a model
- race-condition: a lock, atomic update or transaction around the
  read-then-write of balance/stock/state
- business-logic: server-side enforcement of amount/quantity/state-
  transition invariants (no client-supplied price, no negative transfer)
- auth-flaws: rate limiting, strong random tokens and expiry on
  login/token/password-reset flows"""

_BASE_PROMPT = """\
You are a senior application-security engineer investigating a suspected
{vuln_type} vulnerability at {route} (handler {entrypoint}).

This is a category-B flaw: the evidence is an ABSENT check, not a
dangerous function call. Prove or disprove the absence by comparison.

Absence-comparison playbook — follow in order:
1. get_forward_slice(entrypoint): the handler + all downstream callees'
   source.
2. Inside the slice, look for the check that SHOULD exist for this class
   (see the per-class table below).
3. Not found -> search_code repo-wide for the idiom used elsewhere
   (login_required / requireRole / current_user.id == / [Authorize] ...).
4. Verdict by comparison:
   - Sibling routes have the check, this one doesn't -> absence
     established: is_vulnerable=true. Cite BOTH this route's missing
     spot AND the comparison route's check location (file:line) as one
     evidence entry of kind "absence_comparison", and fill `comparison`
     with the comparison route + check location. That evidence entry
     needs at least 2 refs: where the check is missing and where a
     sibling has it.
   - No route has it -> check app init / middleware registration
     (get_forward_slice won't show it — read_function the app entry
     file: Flask app creation + before_request/blueprint registration,
     Express app.use, Spring filters/interceptors, ASP.NET
     middleware/policies, web.xml). A framework/middleware-level guard
     is defender evidence: downgrade or judge not-vulnerable and cite it.
   - The check exists in the slice -> not-vulnerable, cite it.

{should_be_checks}

Constraints:
- Every claim cites file:line you actually saw via tools; never invent
  checks, routes or guards not present in tool results.
- Evidence refs must be exactly "file:start-end" (e.g.
  "routes/users.py:12-24") — a bare tree-relative path with line
  numbers, no prose, no method signatures.
- For a VULNERABLE verdict, exploit_sketch is a concrete over-reach
  request an attacker would send (e.g. "as user 1, GET /users/2").
- Budget: at most {max_calls} tool calls; on exhaustion submit with a
  lower confidence and note the gap in the verdict reasoning.
- Be honest about uncertainty: if the whole repo lacks the check idiom
  and you could not find the middleware either way, say so.
- Finish by calling submit_b_finding exactly once. This is mandatory."""


def _result_refs(result) -> list[str]:
    """file:line refs mentioned in a tool result (for stats["tool_log"])."""
    text = result if isinstance(result, str) else json.dumps(result, default=str)
    refs = re.findall(r"([\w./-]+\.(?:py|js|ts|java|cs|jsp)):(\d+)", text)
    return sorted({f"{f}:{n}" for f, n in refs})[:30]


_BUDGET_WARNING = (
    "BUDGET WARNING: only 2 tool calls left for this hypothesis — call "
    "submit_b_finding NOW with your current evidence."
)


class _ToolGuard:
    """Per-run tool-call counter: injects the budget warning when 2 calls
    remain, and logs every call for the report.py validation layer."""

    def __init__(self):
        self.calls = 0
        self.log: list[dict] = []

    def wrap(self, tool: str, args: dict, result):
        self.calls += 1
        self.log.append({
            "tool": tool,
            "args": {k: str(v)[:120] for k, v in args.items()},
            "refs": _result_refs(result),
        })
        if self.calls == config.WORKER_MAX_TOOL_CALLS - 2:
            if isinstance(result, str):
                return _BUDGET_WARNING + "\n\n" + result
            if isinstance(result, dict):
                return {**result, "_budget_warning": _BUDGET_WARNING}
            if isinstance(result, list):
                return [*result, {"_budget_warning": _BUDGET_WARNING}]
        return result


def build_agent(hyp: Hypothesis, guard: _ToolGuard) -> Agent:
    """The category-B worker agent (one per hypothesis so the prompt can
    carry the route/class). All code-returning tools strip the
    VULN:/SAFE: ground-truth markers (red line §9.2) — unlike the A-class
    investigator's read_function, which is a known M3 leak surface kept
    as-is for comparability."""
    agent = Agent(
        OpenAIChatModel(config.MODEL, provider=OpenAIProvider(
            base_url=config.BASE_URL, api_key=config.API_KEY)),
        deps_type=SastTools,
        instructions=build_instructions(hyp),
        retries=2,
    )

    @agent.tool
    def get_forward_slice(ctx: RunContext[SastTools], entrypoint: str) -> dict | str:
        """Handler + forward-reachable callee source for one entrypoint.
        Accepts a method fullName, a route label ("GET /users/<id>") or a
        bare function name."""
        return guard.wrap("get_forward_slice", {"entrypoint": entrypoint},
                          ctx.deps.get_forward_slice(entrypoint))

    @agent.tool
    def read_function(ctx: RunContext[SastTools], file: str,
                      start: int, end: int) -> str:
        """Read lines start..end (1-based, inclusive) of a source file
        in the target tree, with line numbers."""
        return guard.wrap("read_function",
                          {"file": file, "start": start, "end": end},
                          _strip_gt_tags(ctx.deps.read_function(file, start, end)))

    @agent.tool
    def search_code(ctx: RunContext[SastTools], pattern: str,
                    glob: str | None = None) -> str:
        """Regex search across the target tree (ripgrep, ±2 lines of
        context). Use it to find the check idiom on sibling routes and
        middleware/guard registration."""
        return guard.wrap("search_code", {"pattern": pattern, "glob": glob},
                          _strip_gt_tags(ctx.deps.search_code(pattern, glob)))

    @agent.tool
    def submit_b_finding(ctx: RunContext[SastTools], finding: BFindingSubmission) -> dict:
        """Submit the final verdict for this hypothesis. Call exactly once, last."""
        # confidence_level/stats are placeholders here; the worker
        # recomputes both from the run record (plan §4 mechanical mapping).
        full = finding.model_dump()
        full["confidence_level"] = "LIKELY"
        full["stats"] = {"source": "agent_submit"}
        # hypothesis echoed back verbatim by the caller, never by the LLM
        full["hypothesis"] = hyp.model_dump()
        return ctx.deps.submit_b_finding(full)

    return agent


def build_instructions(hyp: Hypothesis) -> str:
    """Per-hypothesis system prompt (route/class/entrypoint filled in)."""
    return _BASE_PROMPT.format(
        vuln_type=hyp.vuln_type,
        route=hyp.route,
        entrypoint=hyp.entrypoint,
        should_be_checks=_SHOULD_BE_CHECKS,
        max_calls=config.WORKER_MAX_TOOL_CALLS,
    )


def build_prompt(hyp: Hypothesis) -> str:
    """User prompt for one hypothesis, from the planner's queue entry."""
    return "\n".join([
        "Investigate this suspected category-B vulnerability.",
        "",
        f"Suspected class: {hyp.vuln_type}",
        f"Route: {hyp.route}",
        f"Entrypoint: {hyp.entrypoint} — pass this (or the route label) "
        "as entrypoint to get_forward_slice.",
        f"Trigger features (planner): {hyp.trigger_features}",
        f"Planner rationale: {hyp.rationale}",
        "",
        "Run the absence-comparison playbook, then call submit_b_finding.",
    ])


def _extract_submission(messages) -> BFindingSubmission | None:
    """The submission the agent made via the submit_b_finding tool call
    (latest valid one wins) — same pattern as
    investigator._extract_submission."""
    for msg in reversed(messages):
        for part in getattr(msg, "parts", []):
            if isinstance(part, ToolCallPart) and part.tool_name == "submit_b_finding":
                try:
                    args = part.args_as_dict()
                    # a single BaseModel tool param is flattened by
                    # pydantic-ai into the top-level args object
                    return BFindingSubmission.model_validate(
                        args.get("finding", args))
                except Exception:
                    continue
    return None


def _synthesized(hyp: Hypothesis, reason: str) -> BFindingSubmission:
    """Honest placeholder when the agent could not submit (budget/timeout/
    crash): not vulnerable at low confidence, gap noted in reasoning."""
    return BFindingSubmission(
        verdict=Verdict(
            is_vulnerable=False,
            confidence=0.1,
            reasoning=f"Investigation incomplete: {reason}. "
                      "Recorded as not vulnerable with minimal confidence; "
                      f"the hypothesis was {hyp.vuln_type} at {hyp.route}."),
        evidence=[],
    )


async def investigate_hypothesis(hyp: Hypothesis, tools: SastTools,
                                 token_budget: int) -> BFinding:
    """Run the worker agent over one hypothesis and finalize the BFinding
    (confidence_level + stats added here, never by the LLM)."""
    stats = {
        "tool_calls": 0, "tokens": 0, "requests": 0, "seconds": 0.0,
        "budget_hit": False, "timeout_hit": False, "status": "submitted",
        "tool_log": [],
    }
    guard = _ToolGuard()
    agent = build_agent(hyp, guard)
    start = time.monotonic()
    submission: BFindingSubmission | None = None
    attempts = 2  # one retry on timeout (transient API slowness)
    while attempts > 0:
        attempts -= 1
        try:
            result = await asyncio.wait_for(
                agent.run(
                    build_prompt(hyp),
                    deps=tools,
                    usage_limits=UsageLimits(
                        request_limit=config.WORKER_MAX_TOOL_CALLS,
                        total_tokens_limit=max(token_budget, 1),
                    ),
                ),
                timeout=config.WORKER_TIMEOUT_SECONDS,
            )
            usage = result.usage
            stats["tool_calls"] = usage.tool_calls or guard.calls
            stats["requests"] = usage.requests
            stats["tokens"] += usage.total_tokens or (
                (usage.input_tokens or 0) + (usage.output_tokens or 0))
            submission = _extract_submission(result.all_messages())
            if submission is None:
                stats["status"] = "no_submission"
            break
        except UsageLimitExceeded:
            stats["budget_hit"] = True
            stats["status"] = "budget_exhausted"
            break
        except asyncio.TimeoutError:
            stats["timeout_hit"] = True
            stats["status"] = "timeout" if attempts == 0 else stats["status"]
        except Exception as e:  # transient API failure: one retry (M3 lesson)
            stats["status"] = f"error: {type(e).__name__}: {e}"
            if attempts > 0:
                continue
            break
    stats["seconds"] = round(time.monotonic() - start, 1)
    stats["tool_log"] = guard.log

    if submission is None:
        submission = _synthesized(hyp, stats["status"])

    return BFinding(
        hypothesis=hyp,
        verdict=submission.verdict,
        confidence_level=assign_confidence_level_b(
            submission.verdict, submission.evidence),
        evidence=submission.evidence,
        exploit_sketch=submission.exploit_sketch,
        sanitizer_notes=submission.sanitizer_notes,
        comparison=submission.comparison,
        stats=stats,
    )
