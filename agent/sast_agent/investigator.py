"""Per-sink investigation agent (AGENT_MVP_PLAN.md §6/§6A, milestones M2+M3).

One pydantic-ai Agent (DeepSeek, OpenAI-compatible — same setup as
scripts/llm_judge_sink_chains.py) investigates one InvestigationBrief at a
time. A fresh agent is built per sink so that:

- drill-down tools (read_function / search_code / joern_query /
  get_repo_map) are mounted ONLY for GAP_* briefs (§6A loop control);
- a per-run tool-call counter can inject the "submit NOW" budget warning
  when 2 calls remain (§6A 循环控制).

Budget enforcement (§6): MAX_TOOL_CALLS_PER_SINK via UsageLimits
(request_limit), SINK_TIMEOUT_SECONDS via asyncio.wait_for, and the
MAX_TOTAL_LLM_TOKENS remainder passed in per run by the caller. Budget or
timeout exhaustion produces a synthesized honest Finding (low confidence,
noted in stats) instead of a crash.

Every tool call is recorded in stats["tool_log"] (name, args, file:line
refs touched) so report.py can mechanically validate drilled evidence
paths (§6A 校验层).

Usage:
    from sast_agent.investigator import investigate_sink
    finding = await investigate_sink(brief, tools, token_budget=100_000)
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
from .contracts import Chain, Evidence, Finding, Gap, InvestigationBrief, Sink, Verdict
from .report import assign_confidence_level
from .tools import SastTools

# Ground-truth marker comments (`// VULN: id` / `# SAFE: id`) must never
# reach the LLM (red line §9.2 — snippet validation as in the judges).
# The tag portion is dropped anywhere on the line (not only at line start):
# read_function output prefixes lines with "  12: " and search_code returns
# rg-formatted "path:12:content", so a ^-anchored pattern misses both.
_GT_TAG = re.compile(r"(?://|#)\s*(?:VULN|SAFE):[^\n]*")


def _strip_gt_tags(code: str) -> str:
    return _GT_TAG.sub("", code)


class FindingSubmission(BaseModel):
    """What the agent submits via submit_finding. confidence_level and stats
    are filled in by the investigator (report.py mapping), never by the LLM."""

    sink: Sink
    chain: Chain | None
    verdict: Verdict
    evidence: list[Evidence]
    exploit_sketch: str | None = None
    sanitizer_notes: str | None = None


_BASE_PROMPT = """\
You are a senior application-security engineer investigating ONE suspected
vulnerability in a web application, found by a static-analysis pipeline
(Semgrep located the sink, Joern traced call chains and data flows).

Your job:
1. Pull the evidence with your tools, passing the exact sink id you are
   given.
2. If the chain is complete and taint confirmed, verify semantically
   (is the input really attacker-controlled? is there EFFECTIVE
   sanitization on the path?) and submit the finding.
3. Decide whether attacker-controlled input from the HTTP entrypoint can
   reach the sink's dangerous argument without effective sanitization.
   Parameterized queries, escaping, allow-lists and disabled-entity parsers
   count as sanitization; superficial or bypassable checks do NOT.
   Parser configurations that DISABLE entity/DTD resolution (e.g.
   noent:false, resolve_entities=False, secure-processing parsers) count
   as effective sanitization — do not treat theoretical engine-specific
   bypasses as exploitable without concrete evidence in the code.
   Concretely for libxmljs: `{{ noent: false }}` (or omitting `noent`)
   means entities are NOT substituted, and that parse call is NOT
   vulnerable — judging it vulnerable on parameter-entity/DTD theory
   alone, without an entity-enabling option visible in the code, is a
   FALSE POSITIVE. Only an explicit entity-enabling configuration
   (e.g. `noent: true`, `resolve_entities: true`) makes an XML parse
   sink vulnerable.
   A confirmed taint flow is dataflow evidence, NOT a verdict: check HOW
   the sink is invoked. A hardened variant or safe wrapper (parameterized
   API, entity-disabling parser options, a library/alias that is the safe
   counterpart of the dangerous one) means not vulnerable even with a
   confirmed flow; conversely a parser explicitly configured to resolve
   entities or a raw/unsafe API variant stays vulnerable.
   When the sink has several chains with different sanitization outcomes,
   submit the chain your verdict is about in `chain` and describe the
   sanitized chains in sanitizer_notes.
4. Finish by calling submit_finding exactly once. This is mandatory.

Constraints:
- Base every claim on code you actually saw in tool results.
- Evidence refs must be exactly "file:start-end" (e.g.
  "services/userService.js:5-13") — a bare tree-relative path with line
  numbers, no prose, no method signatures, no parenthetical notes.
  Entries of kind "code_read" must cite lines you actually read, and the
  identifiers you name in the summary must appear in those cited lines.
- Never invent functions, sinks or chains not present in tool results.
- Budget: at most {max_calls} tool calls for this sink. The evidence tools
  are cheap and cached — 3-6 calls are typical for straightforward sinks.
- Be honest about uncertainty: a partial path with gaps belongs in the
  verdict reasoning and a lower confidence, not in a confident claim."""

_FLOW_DEAD_PLAYBOOK = """\
5. The screening found a call chain but the dataflow engine could NOT
   confirm a taint flow (GAP_FLOW_DEAD). This is often an engine blind
   spot: a module variable or object field written in one call and read in
   another, or a cross-file parameter the engine cannot resolve. DO NOT
   give up — run the jump-on-store relay:
   a. get_chain_snippets / read_function the sink-side function; find
      where the flow dies: an external variable (module variable, instance
      field) or a parameter value whose producer the engine lost.
   b. search_code for that variable's WRITE sites (assignments — often a
      stage*/set*/init sibling function).
   c. search_code for callers of the writing function to continue back
      toward the HTTP entrypoint. joern_query (callers_of / writes_to /
      reads_of / methods_in_file) can confirm call relationships when text
      search is ambiguous.
   d. Piece the full path together across files, hop by hop: user input ->
      writer call -> stored variable -> reader -> sink. Record ONE
      evidence entry per hop with a real "file:start-end" ref you actually
      read, and state in the reasoning that the path was completed by
      manual relay over an engine blind spot."""

_NO_CHAIN_PLAYBOOK = """\
5. The screening found NO call chain from any HTTP entrypoint to this sink
   (GAP_NO_CHAIN). DO NOT give up — do text-level go-to-definition:
   a. Identify the function containing the sink (get_chain_snippets or
      read_function around the sink line); search_code for its callers.
   b. read_function each caller; if it is not an HTTP route handler,
      search_code for ITS callers; repeat until you reach a route handler.
   c. get_repo_map gives the route table — use it to attribute the chain
      to a concrete route; joern_query callers_of / methods_in_file can
      help when text search is ambiguous.
   d. Record one evidence entry per hop with real "file:start-end" refs.
      If the chain still does not reach an entrypoint after honest effort,
      say so and lower confidence."""

_GAP_EXPLAIN = {
    "OK": "a call chain to an HTTP entrypoint exists AND the dataflow "
          "engine confirmed a taint flow — verify semantically and judge.",
    "GAP_NO_CHAIN": "backward call-graph tracing reached no HTTP entrypoint "
                    "for this sink.",
    "GAP_FLOW_DEAD": "a call chain exists, but the dataflow engine did not "
                     "confirm a taint flow (engine blind spot or dead flow).",
    "GAP_MISSING_STORE": "chain/flow exist but a field write site is missing "
                         "from the chain.",
}

_BUDGET_WARNING = (
    "BUDGET WARNING: only 2 tool calls left for this sink — call "
    "submit_finding NOW with your current evidence."
)


def _result_refs(result) -> list[str]:
    """file:line refs mentioned in a tool result (for stats["tool_log"])."""
    text = result if isinstance(result, str) else json.dumps(result, default=str)
    refs = re.findall(r"([\w./-]+\.(?:py|js|ts|java|cs|jsp)):(\d+)", text)
    return sorted({f"{f}:{n}" for f, n in refs})[:30]


class _ToolGuard:
    """Per-run tool-call counter: injects the §6A budget warning when 2
    calls remain, and logs every call for the report.py validation layer."""

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
        if self.calls == config.MAX_TOOL_CALLS_PER_SINK - 2:
            if isinstance(result, str):
                return _BUDGET_WARNING + "\n\n" + result
            if isinstance(result, dict):
                return {**result, "_budget_warning": _BUDGET_WARNING}
            if isinstance(result, list):
                return [*result, {"_budget_warning": _BUDGET_WARNING}]
        return result


def build_agent(gap: Gap | None, guard: _ToolGuard) -> Agent:
    """The investigation agent. Drill-down tools are mounted ONLY when a
    gap is set (§6A: unavailable for OK sinks)."""
    agent = Agent(
        OpenAIChatModel(config.MODEL, provider=OpenAIProvider(
            base_url=config.BASE_URL, api_key=config.API_KEY)),
        deps_type=SastTools,
        instructions=_BASE_PROMPT.format(max_calls=config.MAX_TOOL_CALLS_PER_SINK)
        + ("\n" + _FLOW_DEAD_PLAYBOOK if gap == Gap.GAP_FLOW_DEAD else "")
        + ("\n" + _NO_CHAIN_PLAYBOOK if gap == Gap.GAP_NO_CHAIN else ""),
        retries=2,
    )

    @agent.tool
    def get_chains(ctx: RunContext[SastTools], sink_id: str) -> list[dict]:
        """Call chains from HTTP entrypoints to the sink (possibly empty)."""
        return guard.wrap("get_chains", {"sink_id": sink_id},
                          ctx.deps.get_chains(sink_id))

    @agent.tool
    def get_taint_flows(ctx: RunContext[SastTools], sink_id: str) -> dict:
        """Dataflow confirmation: confirmed flag + readable flow paths."""
        return guard.wrap("get_taint_flows", {"sink_id": sink_id},
                          ctx.deps.get_taint_flows(sink_id))

    @agent.tool
    def get_chain_snippets(ctx: RunContext[SastTools], sink_id: str) -> list[dict]:
        """Source code of every function on the sink's chains."""
        records = ctx.deps.get_chain_snippets(sink_id)
        for rec in records:
            for snip in rec.get("snippets", []):
                snip["code"] = _strip_gt_tags(snip.get("code", ""))
        return guard.wrap("get_chain_snippets", {"sink_id": sink_id}, records)

    if gap:

        @agent.tool
        def read_function(ctx: RunContext[SastTools], file: str,
                          start: int, end: int) -> str:
            """Read lines start..end (1-based, inclusive) of a source file
            in the target tree, with line numbers."""
            return guard.wrap("read_function",
                              {"file": file, "start": start, "end": end},
                              ctx.deps.read_function(file, start, end))

        @agent.tool
        def search_code(ctx: RunContext[SastTools], pattern: str,
                        glob: str | None = None) -> str:
            """Regex search across the target tree (ripgrep, ±2 lines of
            context). Use it to find write sites and callers."""
            return guard.wrap("search_code", {"pattern": pattern, "glob": glob},
                              ctx.deps.search_code(pattern, glob))

        @agent.tool
        def joern_query(ctx: RunContext[SastTools], template: str, arg: str):
            """Parameterized CPG query: callers_of(methodName),
            writes_to(varName), reads_of(varName), methods_in_file(file)."""
            return guard.wrap("joern_query", {"template": template, "arg": arg},
                              ctx.deps.joern_query(template, arg))

        @agent.tool
        def get_repo_map(ctx: RunContext[SastTools]) -> str:
            """Repository map: directory tree, HTTP route table, symbols."""
            return guard.wrap("get_repo_map", {}, ctx.deps.get_repo_map())

    @agent.tool
    def submit_finding(ctx: RunContext[SastTools], finding: FindingSubmission) -> dict:
        """Submit the final verdict for this sink. Call exactly once, last."""
        # confidence_level/stats are placeholders here; the investigator
        # recomputes both from the run record (plan §6 loop control).
        full = finding.model_dump()
        full["confidence_level"] = "LIKELY"
        full["stats"] = {"source": "agent_submit"}
        return ctx.deps.submit_finding(full)

    return agent


def build_prompt(brief: InvestigationBrief) -> str:
    """User prompt for one sink, from the screening brief."""
    sink = brief.sink
    cwe = brief.semgrep.get("cwe", "")
    return "\n".join([
        "Investigate this suspected vulnerability.",
        "",
        f"Sink id: `{sink.id}` — pass this exact string as sink_id to your tools.",
        f"Suspected class: {sink.vuln_type} (semgrep rule: {sink.rule}"
        + (f", CWE-{cwe}" if cwe else "") + ")",
        f"Sink call: `{sink.name}` at {sink.file}:{sink.line}",
        f"Screening classification: {brief.gap.value} — "
        + _GAP_EXPLAIN.get(brief.gap.value, ""),
        "",
        "Pull the chains, taint flows and source snippets with your tools, "
        "then decide and call submit_finding.",
    ])


def _extract_submission(messages) -> FindingSubmission | None:
    """The Finding the agent submitted via the submit_finding tool call
    (latest valid one wins)."""
    for msg in reversed(messages):
        for part in getattr(msg, "parts", []):
            if isinstance(part, ToolCallPart) and part.tool_name == "submit_finding":
                try:
                    args = part.args_as_dict()
                    # a single BaseModel tool param is flattened by
                    # pydantic-ai into the top-level args object
                    return FindingSubmission.model_validate(args.get("finding", args))
                except Exception:
                    continue
    return None


def _synthesized(brief: InvestigationBrief, reason: str) -> FindingSubmission:
    """Honest placeholder when the agent could not submit (budget/timeout/
    crash): not vulnerable at low confidence, gap noted in reasoning."""
    return FindingSubmission(
        sink=brief.sink,
        chain=brief.chains[0] if brief.chains else None,
        verdict=Verdict(
            is_vulnerable=False,
            confidence=0.1,
            reasoning=f"Investigation incomplete: {reason}. "
                      "Recorded as not vulnerable with minimal confidence; "
                      "the screening gap for this sink is "
                      f"{brief.gap.value}."),
        evidence=[],
    )


async def investigate_sink(brief: InvestigationBrief, tools: SastTools,
                           token_budget: int) -> Finding:
    """Run the investigation agent over one brief and finalize the Finding
    (confidence_level + stats added here, never by the LLM)."""
    stats = {
        "tool_calls": 0, "tokens": 0, "requests": 0, "seconds": 0.0,
        "budget_hit": False, "timeout_hit": False, "status": "submitted",
        "tool_log": [],
    }
    gap = brief.gap if brief.gap != Gap.OK else None
    guard = _ToolGuard()
    agent = build_agent(gap=gap, guard=guard)
    start = time.monotonic()
    submission: FindingSubmission | None = None
    attempts = 2  # one retry on timeout (transient API slowness)
    while attempts > 0:
        attempts -= 1
        try:
            result = await asyncio.wait_for(
                agent.run(
                    build_prompt(brief),
                    deps=tools,
                    usage_limits=UsageLimits(
                        request_limit=config.MAX_TOOL_CALLS_PER_SINK,
                        total_tokens_limit=max(token_budget, 1),
                    ),
                ),
                timeout=config.SINK_TIMEOUT_SECONDS,
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
        except Exception as e:  # model/API failure: honest error finding
            stats["status"] = f"error: {type(e).__name__}: {e}"
            break
    stats["seconds"] = round(time.monotonic() - start, 1)
    stats["tool_log"] = guard.log

    if submission is None:
        submission = _synthesized(brief, stats["status"])

    # keep the pipeline's first chain when the agent submitted none
    chain = submission.chain or (brief.chains[0] if brief.chains else None)
    # all chains the sink has — scoring (report.py) expands the finding over
    # them, mirroring the judge's per-chain verdicts
    stats["chains"] = [c.model_dump() for c in (brief.chains or [])]
    return Finding(
        sink=submission.sink,
        chain=chain,
        verdict=submission.verdict,
        confidence_level=assign_confidence_level(brief, submission.verdict),
        evidence=submission.evidence,
        exploit_sketch=submission.exploit_sketch,
        sanitizer_notes=submission.sanitizer_notes,
        stats=stats,
    )
