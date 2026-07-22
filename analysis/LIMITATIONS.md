# Known Limitations & Future Work

Findings from the 2026-07 session that built and validated
`analysis/joern/taint_confirm.sc` (Semgrep sink -> call-graph backward trace ->
DFG confirmation) across all four targets. Raw outputs: `/tmp/taint_{py,java,js,cs}.jsonl`.

## 1. Source-coverage gaps (taint sources)

- ~~**Python: Flask path parameters are not sources.**~~ **FIXED (D1,
  2026-07)** — see DECISIONS.md. Route-placeholder handler params
  (Flask `<...>`, FastAPI `{...}`) are now sources; pysrc2cpg has no
  decorator annotations, so handlers are resolved as the next `def` after
  the route call's line. Source coverage was broadened per language at the
  same time (JAX-RS annotations, Koa/Fastify/Hapi accessors, minimal-API
  C# actions). Still uncovered: Django URLconf path params, file uploads,
  websocket/CLI inputs.
- ~~**Java: Semgrep line-hint off-by-one cost us `java-ssti-01`.**~~
  **FIXED (D2, 2026-07)** — sink matching is now name-first within a ±3
  window (constructor-aware); `new Template(...)` is picked correctly.
  Side effect: config-constructor sinks (`XMLParser(resolve_entities=True)`)
  now match their own node and report UNCONFIRMED when taint enters via the
  sibling parse call — the parse call (`fromstring`) CONFIRMS separately, so
  the vuln is still caught.

## 2. Dataflow-engine gaps (Joern OSS)

- **Instance fields ARE tracked; module-scope variables are NOT.** Python/Java/
  C# deep chains (`self._pending_name`, `this._target`) confirm fine. JS
  `js-sqli-02` (module-level `let pendingName` written by `stageName`, read by
  `findStaged`) does NOT confirm — the flow dies at the module-variable
  store/load across files. Candidate fixes: Jump-on-Field for module variables
  (backward DFG hits a module-var read -> jump to all writes of the same var ->
  continue from RHS), or LLM fallback.
  Update (2026-07): the CALL-CHAIN side of this case is fixed — the NO_CHAIN
  was caused by jssrc2cpg ghost callees for require-imported calls, repaired
  via import-binding edge synthesis in the two backward scripts (see
  DECISIONS.md D5). This bullet now concerns only `taint_confirm.sc`
  dataflow confirmation, which is still open.
- **C# cross-file flows are lost.** In-controller sinks CONFIRM; anything
  crossing into `Services/` (`cs-cmdi-02`, `cs-path-traversal-01`, plus
  `cs-xss-01`/`cs-ssti-01` line noise) stays UNCONFIRMED. This is a
  csharpsrc2cpg frontend limitation, not a rule problem — do not "fix" rules
  to force results.
  Update (2026-07): the CALL-CHAIN side is fixed — the root cause was call
  NODES dropped for `_svc.Method()` nested inside `Ok(...)`; repaired with
  a source-text + field-type fallback in the two backward scripts and in
  `extract_entrypoint_snippets.sc` (forward direction; see DECISIONS.md
  D7), taking cs A recall to 10/10. This bullet now concerns only
  `taint_confirm.sc` dataflow confirmation, which is still open.

## 3. Pipeline/structural limitations

- **Sanitizers are invisible to dataflow (by design).** `parse_xml_safe`
  (defusedxml) and `read_whitelisted` (allow-list) still CONFIRM. These
  type-B/C false positives are the LLM layer's job; a CFG-dominance check
  ("guard dominates sink") could mechanize part of it later.
- **Backward chains miss the write side of field passing.** The sink-up walk
  includes `find_staged`/`query_unsafe` but not the sibling `stage_name` call
  that stores the taint. Snippets given to the LLM lack the store site; the
  LLM must infer it (usually possible, but it's a gap).
- **Forward script marks sinks by name only** and over-approximates:
  `query_safe`'s parameterized `execute@27` gets tagged SINK. Semgrep's
  shape-aware rules are the better sink oracle; keep name-tagging for display
  only.
- **Name-based Semgrep rules flag intermediate calls** (e.g. `db.query` inside
  `userService.js`) in addition to the real sink (`pool.query`). Harmless but
  noisy; could be deduped by "is this call's body just forwarding to another
  flagged sink".
- **JS flow attribution works only for handlers registered directly as route
  lambdas.** Anything registered via variable/indirection resolves to
  `<lambda>N` without a route label.
- **Python frontend stores no method source** (`method.code == "<empty>"`), so
  `extract_chain_snippets.sc` slices files from disk via `SRC_ROOT`; CPG
  `lineNumberEnd` overruns slightly and bleeds neighboring comments into
  snippets.
- ~~**Flow output is capped at 5 per sink** and dedup is by node signature;
  duplicate-path noise can crowd out distinct routes (observed on
  `db/index.js:13` where 4 admin-DELETE dups filled the list).~~ **FIXED
  (D4, 2026-07)** — dedup by signature + cap of 3 flows per entrypoint;
  no global per-sink cap anymore.
- **Sinks with no call chain used to vanish from reports.** `chain_report.py`
  now emits NO_CHAIN rows for them (observed: 3 cs `Services/` sinks from
  dropped csharpsrc2cpg CALL edges, 3 js intermediate/indirection sinks).

## 4. Discussed but not implemented (ideas backlog)

- **Name-based call-site fallback** when CALL edges are missing (call graph
  gaps in dynamic languages): walk `cpg.call.name("<methodName>")` instead of
  resolved `.caller` edges. Trades precision (same-name collisions) for
  recall.
- **Jump-on-Parameter / Jump-on-Field manual traversal** (see session
  discussion): mostly redundant with `reachableByFlows`, still relevant for
  module-variable fields and as a lightweight mode without the dataflow
  overlay.
- ~~**Chain-level confirmation report**: join `backward_from_sinks` chains
  with `taint_confirm` flows to mark each *entrypoint->sink chain* (not just
  each sink) CONFIRMED/UNCONFIRMED.~~ **DONE (D3, 2026-07)** —
  `CHAINS_JSON` side output + `scripts/chain_report.py`.
- **Forward dataflow from sources** to discover taint-driven sinks without
  Semgrep (source -> any sensitive call), complementing sink-first analysis.
- **Category B (business logic) remains LLM-only**: CFG-based checks for
  TOCTOU (check-then-act without lock) and sanitizer dominance were sketched
  but not built.
- **Uncovered source kinds**: Flask path params (above), file uploads,
  websocket/CLI inputs — out of scope for the current web-only taxonomy.
