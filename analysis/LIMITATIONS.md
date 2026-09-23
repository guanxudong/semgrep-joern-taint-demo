# Known Limitations & Future Work

Findings from the 2026-07 session that built and validated
`analysis/joern/taint_confirm.sc` (Semgrep sink -> call-graph backward trace ->
DFG confirmation) across all four targets. Raw outputs: `/tmp/taint_{py,java,js,cs}.jsonl`.

Scope (updated 2026-09-23): §§1–3 are the factual engine/pipeline record —
engine-side work was dropped 2026-09-10 in favor of the LLM/agent layer,
which has since been built (M0–M8, `docs/AGENT_MVP_PLAN.md`). The live backlog
is §4 (agent/LLM-layer limitations); the post-MVP roadmap (M9+) lives in
`plan.md`.

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

Update (2026-09-10, both bullets above): the remaining dataflow-side gaps
were dropped as work items — the agent layer (M3 drill-down + M4 verifier)
covers them at the recall ceiling, and an engine fix would only relabel
LIKELY→CONFIRMED on those few cases without changing any verdict. They stay
documented here as factual engine limitations, not planned work.

## 3. Pipeline/structural limitations

- **Sanitizers are invisible to dataflow (by design).** `parse_xml_safe`
  (defusedxml) and `read_whitelisted` (allow-list) still CONFIRM. These
  type-B/C false positives are the LLM layer's job; a CFG-dominance check
  ("guard dominates sink") could mechanize part of it later.
- **Backward chains miss the write side of field passing.** The sink-up walk
  includes `find_staged`/`query_unsafe` but not the sibling `stage_name` call
  that stores the taint. Snippets given to the LLM lack the store site; the
  LLM must infer it (usually possible, but it's a gap).
  Update (2026-09-10): the M3 agent drill-down playbook covers this
  dynamically (jump-on-store relay via `search_code`) with violation-free
  evidence and recall at the ceiling — the planned mechanical snippet
  enrichment was dropped as it would change no verdict (DECISIONS.md D6).
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

## 4. Agent/LLM-layer limitations (live backlog)

With the agent loop in place (M0–M8, `docs/AGENT_MVP_PLAN.md`), the open
weaknesses now live in the judgment/agent layer, not the engine. Evidence
for each item: PROGRESS.md (M0–M8 entries) and `agent/HANDOFF.md`.

- **Judgment-layer model drift.** DeepSeek endpoint drift has flipped
  verdicts (A-class FNs java-cmdi-01/02; safe-02 flipped to FP on 4
  targets) and forced a baseline re-pin (2026-08). Every LLM verdict is
  model-version-sensitive; the regression gate only tolerates
  baseline-known drift, so a silent model change can mask a real
  regression or manufacture a fake one.
- **Persistent known FP: safe-02 (all targets).** The ownership-checked
  IDOR sample is FP'd by the B-class judge/worker on every target
  (baseline-known, tolerated by the gate). Unsolved.
- **Verifier asymmetry.** Adversarial review (attacker/defender) only runs
  on vulnerable verdicts — a not-vulnerable first pass gets no second
  look, so FNs have no safety net. The verifier also multiplies token
  spend roughly 2–3× (M4 regression numbers).
- **Cost and budget truncation.** The B-class worker runs ~2M+ tokens per
  target; WORKER_MAX_TOOL_CALLS=15 and per-investigation timeouts truncate
  deep investigations and force LIKELY-with-gaps submissions. This is the
  main precision ceiling as targets scale up.
- **Hardcoded coverage assumptions.** Python entrypoint detection assumes
  a `(routes|api)/*.py` layout (widened for the enterprise pilot, D12);
  the planner's trait→class mappings are framework-specific. New
  layouts/frameworks need manual extension — the taxonomy checklist makes
  unexamined routes visible but does not examine them.
- **Benchmark hygiene is a class of issue, not a fixed bug.** Tool-output
  channels keep finding new GT-label leak paths (M7 acceptance:
  line-numbered rg output bypassed the anchored strip regex). Every new
  tool or output format must have the strip verified against it.
- **Enterprise validation gap.** On the layered python-flask-enterprise
  target joern confirms only 13/25 chains (52%), and the LLM judge + full
  agent run is still pending — drill-down load on real-world code is
  extrapolated from the small targets, not measured.

## 5. Ideas backlog (engine side)

Pruned 2026-09-10. Removed entries and why:

- *Name-based call-site fallback* — implemented per language as D5 (JS
  import-binding repair) and D7 (C# source-text fallback); see DECISIONS.md.
- *Chain-level confirmation report* — DONE 2026-07 (D3): `CHAINS_JSON` side
  output + `scripts/chain_report.py`.
- *Forward dataflow from sources* / *CFG-based checks for TOCTOU and
  sanitizer dominance* / *new source kinds* — decided against or deferred;
  rationale lives in DECISIONS.md ("Decided against / deferred"), not
  repeated here.

- *Jump-on-Parameter / Jump-on-Field manual traversal* — dropped 2026-09-10:
  its only real justification was as the candidate fix for the two dataflow
  gaps in §2, which were dropped the same day (agent layer covers them at
  the recall ceiling; an engine fix would change no verdict).

**No open engine-side items.** The live backlog is §4 (agent/LLM layer);
the post-MVP roadmap (M9+) lives in `plan.md` at the repo root.

## 6. Language coverage

- **The pipeline assumes both a Semgrep grammar and a Joern frontend per
  target language.** For a language missing both (e.g. Perl — absent from
  Semgrep's GA/beta/experimental lists, no Joern frontend), A-class screening
  dies at CPG build (`ensure_cpg`) and the B-class worker at
  `get_forward_slice`; only the tree-sitter repo map and the grep/read tools
  survive. PHP is NOT such a case — Joern ships php2cpg (needs a local PHP
  runtime) and Semgrep PHP is GA, so PHP would be a full-pipeline (tier-1)
  addition if ever scheduled. Tiered strategy and the degraded agent-only
  mode (tier 3) are designed, not implemented:
  `docs/perl-degraded-mode-design.md`; decision: DECISIONS.md D10
  (2026-09-14).
