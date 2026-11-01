"""Tracer: the LLM-guided trace-continuation state machine (A-class v2).

Replaces the investigator's free-form drill-down playbooks with a
deterministic orchestrator + structured LLM calls:

- the orchestrator holds the TraceState (the dossier) and executes every
  engine step itself via TraceEngine;
- the LLM answers ONE PromptedOutput(TraceStep) per round: resolve last
  round's candidates (each accepted hop needs a disk-checkable
  justify_ref), assess completeness, issue at most one directive;
- when the path is complete (or honestly dead / out of budget), ONE more
  structured call (PromptedOutput(VerdictOut)) gives the semantic verdict.

LLM-call count per sink ≈ trace steps + 1 verdict, versus dozens of
tool round-trips in the free-agent design — and no full-history replay,
which is where the M5 token bills came from.

Usage:
    async def trace_sink(brief, engine, token_budget)
"""

import asyncio
import re
import time

from pydantic_ai import Agent, UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.output import PromptedOutput
from pydantic_ai.providers.openai import OpenAIProvider

from . import config, pipeline
from .contracts import Chain, Finding, Gap, InvestigationBrief, Verdict
from .report import assign_confidence_level
from .trace_engine import TraceEngine, rows_to_candidates
from .trace_prompts import (STEP_INSTRUCTIONS, VERDICT_INSTRUCTIONS,
                            build_step_prompt, build_verdict_prompt)
from .trace_schema import (Candidate, Edge, Hop, StepAssessment, TraceState,
                           TraceStatus, TraceStep, VerdictOut)

MAX_CANDIDATES_SHOWN = 8
CANDIDATE_SNIPPET_LINES = 60
HOP_SOURCE_LINES = 80
MAX_HOP_SOURCES = 8
MAX_VERDICT_SOURCES = 14
EXTRA_CONTEXT_MAX_CHARS = 4000


def _model() -> OpenAIChatModel:
    return OpenAIChatModel(config.MODEL, provider=OpenAIProvider(
        base_url=config.BASE_URL, api_key=config.API_KEY))


def _step_agent() -> Agent:
    return Agent(_model(), output_type=PromptedOutput(TraceStep),
                 instructions=STEP_INSTRUCTIONS, retries=2)


def _verdict_agent() -> Agent:
    return Agent(_model(), output_type=PromptedOutput(VerdictOut),
                 instructions=VERDICT_INSTRUCTIONS, retries=2)


# Module-level indirection so tests and --dry-run can stub the LLM.
async def _ask_step(prompt: str, token_budget: int) -> tuple[TraceStep, int]:
    result = await _step_agent().run(
        prompt,
        usage_limits=UsageLimits(total_tokens_limit=max(token_budget, 1)))
    return result.output, result.usage.total_tokens or 0


async def _ask_verdict(prompt: str, token_budget: int) -> tuple[VerdictOut, int]:
    result = await _verdict_agent().run(
        prompt,
        usage_limits=UsageLimits(total_tokens_limit=max(token_budget, 1)))
    return result.output, result.usage.total_tokens or 0


# ---------------------------------------------------------------------------
# seeding & envelope helpers
# ---------------------------------------------------------------------------

def _snippet_index(brief: InvestigationBrief, engine: TraceEngine) -> dict:
    """method fullName -> snippet record from the cached chain snippets.
    Also records the access in the engine's execution log: snippet code is
    shown to the LLM, so the report.py tool_log backing rule needs it."""
    out = {}
    try:
        records = engine.tools.get_chain_snippets(brief.sink.id)
    except Exception:
        return out
    for rec in records:
        for s in rec.get("snippets", []):
            out[s.get("function", "")] = s
    engine.executions.append({
        "tool": "get_chain_snippets",
        "args": {"sink_id": brief.sink.id},
        "refs": [f"{s.get('file')}:{s.get('start_line')}"
                 for s in out.values() if s.get("file")],
    })
    return out


def _seed_state(brief: InvestigationBrief,
                snip_idx: dict) -> TraceState:
    """Seed the dossier from the screening brief. Longest engine chain wins;
    no chain -> the sink's own method is the frontier."""
    state = TraceState(sink=brief.sink, taint=brief.taint)
    chains = brief.chains or []
    if chains:
        best = max(chains, key=lambda c: len(c.path))
        for full_name in best.path:
            s = snip_idx.get(full_name, {})
            state.hops.append(Hop(
                method=full_name, file=s.get("file", ""),
                line=s.get("start_line", 0), line_end=s.get("end_line", 0),
                edge=Edge.ENGINE))
    else:
        state.hops.append(Hop(method=f"{brief.sink.file}:{brief.sink.name}",
                              file=brief.sink.file, line=brief.sink.line,
                              edge=Edge.ENGINE))
    state.frontier = state.hops[0].method
    return state


def _hop_source(engine: TraceEngine, hop: Hop, snip_idx: dict) -> str | None:
    s = snip_idx.get(hop.method)
    if s:
        code = s.get("code", "")
        if code:
            header = f"### {hop.method} ({s.get('file')}:{s.get('start_line')}-{s.get('end_line')})"
            return header + "\n" + "\n".join(code.splitlines()[:HOP_SOURCE_LINES])
    if hop.file and hop.line:
        end = hop.line_end or hop.line + HOP_SOURCE_LINES
        try:
            text = engine.slice_source(hop.file, hop.line, end,
                                       max_lines=HOP_SOURCE_LINES)
        except Exception:
            return None
        return f"### {hop.method} ({hop.file}:{hop.line}-{end})\n{text}"
    return None


def _ref_resolves(engine: TraceEngine, ref: str) -> bool:
    """Cheap precheck of a justify_ref before a hop enters the chain."""
    m = re.match(r"^([\w./-]+\.\w+):(\d+)(?:-(\d+))?$", ref)
    if not m:
        return False
    path = (engine.tree / m.group(1)).resolve()
    if engine.tree.resolve() not in path.parents or not path.is_file():
        return False
    n = len(path.read_text(errors="replace").splitlines())
    start, end = int(m.group(2)), int(m.group(3) or m.group(2))
    return 1 <= start <= end <= n


# ---------------------------------------------------------------------------
# main loop
# ---------------------------------------------------------------------------

async def trace_sink(brief: InvestigationBrief, engine: TraceEngine,
                     token_budget: int) -> Finding:
    """Run the trace state machine over one screening brief, then the
    verdict call, and assemble the Finding (confidence_level + stats are
    computed here, never by the LLM)."""
    stats = {
        "tool_calls": 0, "tokens": 0, "requests": 0, "seconds": 0.0,
        "budget_hit": False, "timeout_hit": False, "status": "traced",
        "tool_log": [],
    }
    start = time.monotonic()
    engine.executions = []
    snip_idx = _snippet_index(brief, engine)
    state = _seed_state(brief, snip_idx)

    # OK sinks (chain + engine-confirmed taint) skip tracing entirely —
    # the verdict call alone decides (same economy as the old gap gate).
    needs_trace = brief.gap != Gap.OK

    candidates: list[Candidate] = []
    extra_context: list[str] = []
    feedback: str | None = None
    route: str | None = None
    llm_error: str | None = None
    recent_directives: list[str] = []
    executed_kinds: set[str] = set()

    # M9.1: for GAP_NO_CHAIN sinks the first envelope carries the engine's
    # dead-end scene (stall method + unresolved call sites) so the LLM
    # starts from facts instead of re-deriving the gap.
    if brief.gap == Gap.GAP_NO_CHAIN:
        de = pipeline.get_dead_ends(engine.target).get(brief.sink.id)
        if de:
            unresolved = "\n".join(
                f"  - {c.get('code')} (receiver: {c.get('receiver') or '?'})"
                for c in de.get("unresolved_calls", [])) or "  (none)"
            extra_context.append(
                "ENGINE DEAD-END SCENE (the backward walk stalled here):\n"
                f"  method: {de.get('method')} ({de.get('file')}:"
                f"{de.get('line')})\n"
                f"  unresolved call sites (engine could not resolve the "
                f"callee):\n{unresolved}")

    def llm_budget_left() -> int:
        return max(token_budget - stats["tokens"], 0)

    try:
        while needs_trace and state.steps < config.MAX_TRACE_STEPS_PER_SINK:
            # ---- assemble the envelope ----
            cand_snippets: dict[str, str] = {}
            for c in candidates[:MAX_CANDIDATES_SHOWN]:
                if c.file and c.line:
                    begin = c.line
                    end = c.line_end or begin + CANDIDATE_SNIPPET_LINES
                    try:
                        cand_snippets[c.id] = engine.slice_source(
                            c.file, begin, end,
                            max_lines=CANDIDATE_SNIPPET_LINES)
                    except Exception:
                        pass
            frontier_src = _hop_source(engine, state.hops[0], snip_idx)
            chain_sources = []
            if brief.gap == Gap.GAP_FLOW_DEAD:
                # call chain exists but the flow died: show every hop so the
                # LLM can spot the store/load relay in round 1
                for h in state.hops[:MAX_HOP_SOURCES]:
                    src = _hop_source(engine, h, snip_idx)
                    if src:
                        chain_sources.append(src)

            prompt = build_step_prompt(
                brief, state, candidates[:MAX_CANDIDATES_SHOWN],
                cand_snippets, frontier_src, chain_sources,
                extra_context, feedback)
            extra_context, feedback = [], None

            step, tok = await _ask_step(prompt, llm_budget_left())
            stats["tokens"] += tok
            stats["tool_calls"] += 1
            state.steps += 1

            # ---- apply candidate resolutions ----
            by_id = {c.id: c for c in candidates}
            bad_selections = []
            for sel in step.resolve_candidates:
                cand = by_id.get(sel.candidate_id)
                if cand is None:
                    bad_selections.append(
                        f"candidate {sel.candidate_id!r} does not exist")
                    continue
                if not _ref_resolves(engine, sel.justify_ref):
                    bad_selections.append(
                        f"justify_ref {sel.justify_ref!r} does not resolve "
                        "to real lines on disk")
                    continue
                hop = Hop(method=cand.method or cand.code[:60],
                          file=cand.file, line=cand.line,
                          line_end=cand.line_end, edge=Edge.LLM_INFERRED,
                          justify_ref=sel.justify_ref)
                state.hops.insert(0, hop)
                state.frontier = hop.method
                if cand.note:  # route label => the head IS an entrypoint
                    route = cand.note
            if bad_selections:
                feedback = ("Some selections were rejected: "
                            + "; ".join(bad_selections))
            candidates = []

            # ---- assessment ----
            if step.assessment == StepAssessment.COMPLETE:
                state.status = TraceStatus.COMPLETE
                state.source_description = step.source_description
                break
            if step.assessment == StepAssessment.DEAD:
                # Mechanical guardrail (impossible in a free-agent loop):
                # a dead verdict is only accepted after at least one
                # broad-recall probe — a name the call graph cannot see is
                # usually registered as a value somewhere, and giving up
                # before checking that is the classic false FN.
                if not executed_kinds & {"find_call_sites", "search_code"}:
                    feedback = (
                        "dead REJECTED: you have not tried any broad-recall "
                        "probe yet. Run find_call_sites or search_code on "
                        "the frontier symbol first — registry/callback "
                        "registrations are value references, not calls, so "
                        "callers_of alone cannot see them.")
                    continue
                state.status = TraceStatus.DEAD
                state.dead_reason = step.rationale
                break

            # ---- execute the directive ----
            d = step.directive
            if d is None:  # schema guarantees one; be lenient anyway
                feedback = "assessment requires a directive; resubmit with one"
                continue
            sig = f"{d.kind}:{d.symbol}:{d.file}:{d.line}"
            repeats = recent_directives.count(sig)
            recent_directives.append(sig)
            if repeats >= 2:
                state.status = TraceStatus.DEAD
                state.dead_reason = (f"no progress: directive {sig} repeated "
                                     "3 times without the path advancing")
                break
            if repeats == 1:
                # An identical directive returns identical rows — pure
                # waste. Reject it and name the avenues not yet tried, so
                # the loop course-corrects instead of burning the budget
                # in a read/retry spiral (the cs-cmdi-02 lesson: it read
                # the same file 3x and died without ever trying
                # writes_to on the staging field).
                untried = [k for k in ("writes_to", "find_call_sites",
                                       "callers_of", "reads_of")
                           if k not in executed_kinds]
                feedback = (
                    f"directive {sig} already ran and did not advance the "
                    f"path — repeating it returns the same result. Pick a "
                    f"DIFFERENT avenue (untried so far: "
                    f"{', '.join(untried) or 'none'}). If the frontier "
                    "method is parameterless but reads an instance field "
                    "or module variable, writes_to(field) is the relay "
                    "probe.")
                continue
            rows, error = await asyncio.to_thread(engine.execute, d,
                                                  brief.sink)
            executed_kinds.add(d.kind)
            if error:
                feedback = f"directive {d.kind} failed: {error}"
                continue
            if d.kind in ("read_file", "search_code"):
                extra_context = [r.get("code", r.get("error", ""))
                                 [:EXTRA_CONTEXT_MAX_CHARS] for r in rows]
            elif d.kind == "trace_back":
                # engine-side continuation: adopt the best chain as engine
                # hops, but the LLM still confirms completeness next round
                if rows:
                    best = max(rows, key=lambda r: len(r.get("path", [])))
                    route = best.get("route") or route
                    for full_name in best.get("path", []):
                        s = snip_idx.get(full_name, {})
                        state.hops.insert(0, Hop(
                            method=full_name, file=s.get("file", ""),
                            line=s.get("start_line", 0),
                            line_end=s.get("end_line", 0), edge=Edge.ENGINE))
                    state.frontier = state.hops[0].method
                    feedback = (f"trace_back reached entrypoint {route!r}; "
                                "the path was extended — confirm complete "
                                "or keep digging")
                else:
                    feedback = (f"trace_back({d.symbol}) reached no "
                                "entrypoint")
            else:
                candidates = rows_to_candidates(rows, d.kind)
                for i, c in enumerate(candidates, 1):
                    c.id = f"c{i}"
                if not candidates:
                    feedback = (f"directive {d.kind}({d.symbol or d.file}) "
                                "returned no candidates")
                    if d.kind == "callers_of":
                        feedback += (
                            ". If the symbol is registered as a VALUE "
                            "(registry/dict/callback), no call site exists — "
                            "probe with find_call_sites or search_code next")

        else:
            if needs_trace:
                state.status = TraceStatus.BUDGET_OUT
                state.dead_reason = (f"trace step budget "
                                     f"({config.MAX_TRACE_STEPS_PER_SINK}) "
                                     "exhausted")
        if not needs_trace:
            state.status = TraceStatus.COMPLETE

        # ---- verdict ----
        # Sources: the traced path PLUS every engine chain's methods
        # (deduped) — a sanitizer visible on one route must not veto the
        # chains the traced path did not take (the py-sqli-01/02 FN:
        # the verdict saw only the int-coerced get_user chain).
        chain_sources = []
        verdict_methods = [h.method for h in state.hops]
        seen_methods: set[str] = set(verdict_methods)
        for c in (brief.chains or []):
            verdict_methods += [m for m in c.path if m not in seen_methods]
            seen_methods.update(c.path)
        for m in verdict_methods[:MAX_VERDICT_SOURCES]:
            src = _hop_source(engine, Hop(method=m), snip_idx)
            if src:
                chain_sources.append(src)
        vprompt = build_verdict_prompt(brief, state, chain_sources)
        vout, tok = await _ask_verdict(vprompt, llm_budget_left())
        stats["tokens"] += tok
        stats["tool_calls"] += 1
        verdict = Verdict(is_vulnerable=vout.is_vulnerable,
                          confidence=vout.confidence, reasoning=vout.reasoning)
        evidence = vout.evidence
        exploit_sketch = vout.exploit_sketch
        sanitizer_notes = vout.sanitizer_notes
        # Anchor the finding (and the verifier after it) to the chain the
        # verdict actually found exploitable, not the seeded-longest one.
        # Prefer the robust chain index; fall back to fuzzy route matching
        # (both directions — route labels vary: "GET /x" vs
        # 'Controller @GetMapping("/x")').
        if vout.is_vulnerable and brief.chains:
            pick = None
            if vout.exploitable_chain is not None \
                    and 1 <= vout.exploitable_chain <= len(brief.chains):
                pick = brief.chains[vout.exploitable_chain - 1]
            elif vout.exploitable_route:
                want = vout.exploitable_route
                for c in brief.chains:
                    labels = [c.route or "", c.entrypoint or ""]
                    if any(want and (want in lab or lab and lab in want)
                           for lab in labels):
                        pick = c
                        break
            if pick is not None:
                route = pick.route or route
                state.hops = [Hop(method=m,
                                  file=snip_idx.get(m, {}).get("file", ""),
                                  line=snip_idx.get(m, {}).get(
                                      "start_line", 0),
                                  line_end=snip_idx.get(m, {}).get(
                                      "end_line", 0),
                                  edge=Edge.ENGINE)
                              for m in pick.path]
                state.frontier = state.hops[0].method
    except UsageLimitExceeded:
        stats["budget_hit"] = True
        stats["status"] = "budget_exhausted"
        verdict = None
    except Exception as e:
        llm_error = f"{type(e).__name__}: {e}"
        stats["status"] = f"error: {llm_error}"
        verdict = None

    if verdict is None:
        verdict = Verdict(
            is_vulnerable=False, confidence=0.1,
            reasoning=f"Investigation incomplete: {stats['status']}. "
                      "Recorded as not vulnerable with minimal confidence.")
        evidence, exploit_sketch, sanitizer_notes = [], None, None

    stats["seconds"] = round(time.monotonic() - start, 1)
    stats["tool_log"] = list(engine.executions)
    stats["trace"] = [h.model_dump() for h in state.hops]
    stats["trace_status"] = state.status.value
    if state.dead_reason:
        stats["trace_dead_reason"] = state.dead_reason
    stats["chains"] = [c.model_dump() for c in (brief.chains or [])]

    chain = None
    if state.hops and (state.status == TraceStatus.COMPLETE or brief.chains):
        head = state.hops[0]
        chain = Chain(
            route=route or (brief.chains[0].route if brief.chains else None),
            entrypoint=head.method,
            path=[h.method for h in state.hops],
        )
    elif brief.chains:
        chain = brief.chains[0]

    return Finding(
        sink=brief.sink,
        chain=chain,
        verdict=verdict,
        confidence_level=assign_confidence_level(brief, verdict),
        evidence=evidence,
        exploit_sketch=exploit_sketch,
        sanitizer_notes=sanitizer_notes,
        stats=stats,
    )
