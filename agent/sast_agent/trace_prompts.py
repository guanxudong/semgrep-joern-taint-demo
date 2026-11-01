"""Prompts for the tracer state machine (A-class v2).

Three prompts:
- STEP_INSTRUCTIONS — the per-round "fill the TraceStep form" instructions
  (candidate resolution + completeness assessment + one directive);
- VERDICT_INSTRUCTIONS — the final semantic judgment once the path is as
  complete as it gets. The sanitizer rules are ported verbatim-in-spirit
  from the original A-class investigation playbook: they were bought with
  real FPs (py-safe-03 hardened wrapper, js-safe-03 libxmljs noent) — do
  not soften.
- build_step_prompt / build_verdict_prompt — assemble the per-round user
  message (the "envelope").

No .format() on the instruction constants: they contain literal braces in
JSON examples (the KeyError: ' noent' lesson from M3).
"""

import json

from .contracts import InvestigationBrief
from .trace_schema import Candidate, TraceState

STEP_INSTRUCTIONS = """\
You are a senior application-security engineer directing a taint trace.
A static pipeline (Semgrep found the sink, the Joern CPG engine traced
call chains) stalled: the call chain or the data flow does not visibly
reach an attacker-controlled source. You decide where the ENGINE digs
next — you never write queries yourself.

Each round you receive an envelope:
- SINK: the dangerous call under investigation;
- PATH SO FAR: every hop with its provenance (engine = from the CPG call
  graph, llm_inferred = a previous round's pick, with the code ref that
  justified it). The head of the path is the current FRONTIER — the
  method closest to the (not yet reached) user-input source;
- FRONTIER SOURCE / CHAIN SOURCES: the actual code of the frontier (and
  other path methods) — base your reasoning ONLY on code you see here;
- CANDIDATES: when the engine returned possible continuations last round,
  each with an id (c1, c2, ...) and a code snippet;
- TAINT FACTS: what the dataflow engine confirmed or failed to confirm.

Fill the TraceStep form:

1. resolve_candidates — for every candidate that IS the correct
   continuation (read its code: receiver type, import binding, DI
   registration, naming), accept it with the justify_ref "file:start-end"
   of the lines that prove it. Reject look-alikes via reject_reason.
   Never accept a candidate whose code you have not seen.
2. assessment:
   - complete: the path now reaches attacker-controlled input (an HTTP
     route handler reading request data, annotated controller params,
     route-placeholder params) AND you can explain how the value flows
     to the sink — including store/load relays through module variables
     or object fields. State the source in source_description.
   - broken: you found where the trail goes cold (a variable whose
     producer is invisible, a call the engine could not resolve, dynamic
     dispatch) — issue ONE directive saying what to dig up next.
   - need_context: you cannot decide without seeing more code — issue
     ONE read_file/search_code directive (the "order a dish" escape
     hatch).
   - dead: honest dead end after real effort — say why in rationale.
     Do NOT invent a continuation to avoid saying dead.
3. directive menu (pick kind, fill symbol/file/line):
   - callers_of(symbol): who calls this function/method;
   - writes_to(symbol): assignments to this variable/field — the
     jump-on-store relay for module variables and object fields whose
     value is written elsewhere;
   - reads_of(symbol): read sites of a variable;
   - find_call_sites(symbol): ALL name-based call sites of a function —
     over-approximate on purpose; use when the call graph is blind
     (dynamic dispatch, reflection, DI) and pick the real one by code;
   - trace_back(symbol): restart the engine's backward BFS from this
     method fullName/name toward HTTP entrypoints;
   - methods_in_file(file): list methods of a file;
   - read_file(file, line): read ~90 lines around line of file;
   - search_code(symbol): regex search across the repo (±2 lines).

Rules:
- ONE directive per round. Digging is cheap; rounds are not infinite.
- A taint flow marked UNCONFIRMED is an engine blind spot until proven
  otherwise — chase the store/load relay before concluding dead.
- PARAMETERLESS FRONTIER: when the frontier method takes no parameters
  (or none that carry the taint) yet its body reads an instance field or
  module-level variable that reaches the sink, the taint ARRIVES VIA A
  WRITE to that field/variable — issue writes_to(field) on it
  immediately. Do NOT conclude "the value is never passed in" just
  because the callee's signature has no parameter for it; C#/Java/Python
  services routinely stage attacker input through `this.field`,
  `self.field` or module globals between two calls.
- Registry / dynamic dispatch: when callers_of(f) returns nothing but f
  clearly IS used, f is probably registered as a VALUE (a dict/registry
  entry like `HANDLERS = {"diag": f}`, a callback list, `getattr`,
  reflection). find_call_sites(f) also covers those references — find the
  registration site, then trace the REGISTRY OBJECT (reads_of(registry))
  to the dispatch site (`HANDLERS.get(x)` / `obj[name]()`), and continue
  from the dispatcher's callers.
- Everything you assert must come from the envelope's code. No invented
  functions, no assumed callers."""

VERDICT_INSTRUCTIONS = """\
You are a senior application-security engineer giving the FINAL verdict
on one suspected vulnerability. The trace is as complete as it gets:
you receive the sink, the full path (engine + LLM-inferred hops with
their justifying code refs), the source code of the path functions, and
the dataflow facts.

Decide: can attacker-controlled input from the entrypoint reach the
sink's dangerous argument WITHOUT effective sanitization?

Sanitization rules (each was bought with a real false positive — apply
them literally):
- Parameterized queries, escaping, allow-lists and disabled-entity
  parsers count as EFFECTIVE sanitization; superficial or bypassable
  checks do NOT.
- Parser configurations that DISABLE entity/DTD resolution (e.g.
  noent:false, resolve_entities=False, secure-processing parsers) count
  as effective sanitization — do not treat theoretical engine-specific
  bypasses as exploitable without concrete evidence in the code.
  Concretely for libxmljs: `{ noent: false }` (or omitting `noent`)
  means entities are NOT substituted, and that parse call is NOT
  vulnerable — judging it vulnerable on parameter-entity/DTD theory
  alone, without an entity-enabling option visible in the code, is a
  FALSE POSITIVE. Only an explicit entity-enabling configuration
  (e.g. `noent: true`, `resolve_entities: true`) makes an XML parse
  sink vulnerable.
- A confirmed taint flow is dataflow evidence, NOT a verdict: check HOW
  the sink is invoked. A hardened variant or safe wrapper (parameterized
  API, entity-disabling parser options, a library/alias that is the safe
  counterpart of the dangerous one) means not vulnerable even with a
  confirmed flow; conversely a parser explicitly configured to resolve
  entities or a raw/unsafe API variant stays vulnerable.
- MULTIPLE CHAINS: when the envelope lists several REACHABLE CHAINS, the
  same sink is reachable from several entrypoints. Judge EACH chain
  separately: the verdict is vulnerable if ANY chain delivers attacker
  input to the dangerous argument without effective sanitization. A
  sanitizer on one route (a type-coercing URL converter, an allow-list
  wrapper) protects ONLY that route — it does not sanitize the other
  chains. When vulnerable, set exploitable_chain to the NUMBER of the
  chain you found exploitable; when not vulnerable, your reasoning must
  say why EACH chain fails to deliver unsanitized input.

Evidence rules:
- Base every claim on code in the envelope. Never invent functions.
- Evidence refs must be exactly "file:start-end" (e.g.
  "services/userService.js:5-13") — bare tree-relative paths with line
  numbers, no prose, no method signatures, no parenthetical notes.
  Entries of kind "code_read" must cite lines you actually saw, and the
  identifiers named in the summary must appear in the cited lines.
- Be honest about uncertainty: a partial path with gaps belongs in the
  reasoning and a lower confidence, not in a confident claim.

Fill VerdictOut: is_vulnerable, confidence (0..1), reasoning (2-4
sentences: the taint path + why exploitable or not), evidence,
exploit_sketch (a concrete triggering request when vulnerable),
sanitizer_notes (the defender-view conclusion), exploitable_chain
(the NUMBER of the exploitable chain when several chains were
listed and the verdict is vulnerable)."""


def _fmt_hops(state: TraceState) -> str:
    if not state.hops:
        return "(no hops yet — tracing starts at the sink's method)"
    lines = []
    for i, h in enumerate(state.hops):
        head = " <- FRONTIER" if i == 0 else ""
        prov = h.edge.value
        ref = f", justify {h.justify_ref}" if h.justify_ref else ""
        loc = f"{h.file}:{h.line}" if h.file else "?"
        lines.append(f"  {i + 1}. {h.method} ({loc}) [{prov}{ref}]{head}")
    return "\n".join(lines)


def _fmt_candidates(cands: list[Candidate], snippets: dict[str, str]) -> str:
    if not cands:
        return "(none this round)"
    out = []
    for c in cands:
        loc = f"{c.file}:{c.line}"
        note = f" | {c.note}" if c.note else ""
        out.append(f"--- {c.id} [{c.kind}] {c.method} ({loc}){note}")
        snip = snippets.get(c.id)
        out.append(snip if snip else f"    {c.code}")
    return "\n".join(out)


def _fmt_taint(brief: InvestigationBrief) -> str:
    t = brief.taint
    if t is None:
        return "no dataflow record for this sink"
    status = "CONFIRMED" if t.confirmed else "UNCONFIRMED"
    flows = "\n".join(f"  - {f}" for f in t.flows[:5]) or "  (no flows)"
    return f"dataflow status: {status}\n{flows}"


def build_step_prompt(brief: InvestigationBrief, state: TraceState,
                      candidates: list[Candidate],
                      candidate_snippets: dict[str, str],
                      frontier_source: str,
                      chain_sources: list[str],
                      extra_context: list[str],
                      feedback: str | None) -> str:
    """Assemble one round's envelope."""
    sink = brief.sink
    parts = [
        f"SINK: `{sink.name}` at {sink.file}:{sink.line} "
        f"(rule {sink.rule}, class {sink.vuln_type})",
        "",
        "PATH SO FAR (head = frontier):",
        _fmt_hops(state),
        "",
        "TAINT FACTS:",
        _fmt_taint(brief),
        "",
        "CANDIDATES from the last engine step:",
        _fmt_candidates(candidates, candidate_snippets),
    ]
    if frontier_source:
        parts += ["", "FRONTIER SOURCE:", frontier_source]
    if chain_sources:
        parts += ["", "CHAIN SOURCES:"] + chain_sources
    if extra_context:
        parts += ["", "ORDERED CONTEXT (you asked for these last round):"] \
            + extra_context
    if feedback:
        parts += ["",
                  "REJECTED LAST ROUND (fix and resubmit):", feedback]
    parts += ["",
              f"Steps used: {state.steps}. Fill the TraceStep form now."]
    return "\n".join(parts)


def build_verdict_prompt(brief: InvestigationBrief, state: TraceState,
                         chain_sources: list[str]) -> str:
    sink = brief.sink
    chains = brief.chains or []
    parts = [
        f"SINK: `{sink.name}` at {sink.file}:{sink.line} "
        f"(rule {sink.rule}, class {sink.vuln_type})",
        "",
        f"TRACE STATUS: {state.status.value}"
        + (f" — {state.dead_reason}" if state.dead_reason else "")
        + (f"\nSOURCE: {state.source_description}"
           if state.source_description else ""),
        "",
        "TRACED PATH (head = entrypoint side):",
        _fmt_hops(state),
    ]
    if chains:
        lines = []
        for i, c in enumerate(chains, 1):
            label = c.route or c.entrypoint or "?"
            lines.append(f"  chain {i} [{label}]: " + " -> ".join(c.path))
        parts += ["",
                  f"REACHABLE CHAINS ({len(chains)} — judge EACH one; one "
                  "exploitable chain makes the sink vulnerable):"] + lines
    parts += [
        "",
        "TAINT FACTS:",
        _fmt_taint(brief),
        "",
        "PATH SOURCES:",
        *chain_sources,
        "",
        "Give the final verdict (VerdictOut).",
    ]
    return "\n".join(parts)


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)
