# Progress

Status of the Semgrep + Joern taint-confirmation pipeline as of 2026-07.
Companion docs: `LIMITATIONS.md` (known gaps), `DECISIONS.md` (what we
decided to do about them).

## Done and validated

- `analysis/joern/taint_confirm.sc` built and validated across all four
  targets: Semgrep sink -> call-graph backward trace -> DFG confirmation.
  Raw outputs: `/tmp/taint_{py,java,js,cs}.jsonl`.
- Instance-field flows confirm correctly in Python / Java / C#
  (`self._pending_name`, `this._target` style deep chains).
- In-controller C# sinks confirm; Python/Java/JS deep chains confirm.
- Supporting scripts in place: `find_entrypoints.sc`,
  `backward_from_sinks.sc`, `forward_from_entrypoints.sc`,
  `extract_chain_snippets.sc` (disk-sliced via `SRC_ROOT` because the Python
  frontend stores no method source), `scripts/semgrep_to_sinks.py`.
- **D1–D4 implemented and re-validated on all four targets** (chain-level
  report: py 22/25, java 21/22, js 22/28, cs 18/25 chains CONFIRMED):
  - D1 (route-parameter sources, `taint_confirm.sc`): python Flask `<...>` /
    FastAPI `{...}` handler params (pysrc2cpg has no decorator annotations —
    handlers resolved as the next `def` after the route call's line); java
    Spring + JAX-RS annotated params; js Koa/Fastify/Hapi accessor calls;
    csharp any `[Http*]`-annotated action's params. Validated:
    `get_user` -> `db.py:16` and `delete_user` -> `db.py:37` now CONFIRM.
  - D2 (sink-name-first matching, `taint_confirm.sc` +
    `backward_from_sinks.sc`): ±3 window, name match ranked
    name < methodFullName (signature stripped) < `new X` code; constructor
    sinks matched by type name. Validated: `java-ssti-01` now picks
    `new Template(...)` (not `new Configuration(...)`) and CONFIRMS.
  - D3 (chain-level report): `backward_from_sinks.sc` emits JSONL via
    `CHAINS_JSON`; new `scripts/chain_report.py` joins chains with taint
    flows into per-chain CONFIRMED/UNCONFIRMED/NO_CHAIN.
  - D4 (flow dedup/cap): 3 flows per entrypoint instead of 5 per sink.
    Validated: `db/index.js:13` keeps the DELETE `/users/:id` chain
    CONFIRMED while the static-SQL GET `/users` chain is correctly
    UNCONFIRMED instead of crowded out.

## Known gaps (details in LIMITATIONS.md)

- Joern OSS dataflow: JS module-level variables not tracked
  (`js-sqli-02`); C# cross-file flows lost past `Services/` (3 sinks report
  NO_CHAIN: `Services/FileService.cs`, `Services/ToolService.cs`) —
  csharpsrc2cpg frontend limit.
- Structural: sanitizers invisible to dataflow (by design, LLM layer's job);
  backward chains miss the write side of field passing (`stage_name` store
  site absent from LLM snippets); forward script over-tags sinks by name;
  Semgrep name-based rules flag intermediate forwarding calls (2 of the 3 js
  NO_CHAIN sinks); JS flow attribution only works for direct route lambdas.
- Config-constructor sinks (e.g. `XMLParser(resolve_entities=True)`) are now
  matched faithfully (D2) but show UNCONFIRMED because taint enters via the
  sibling parse call (`fromstring`), which CONFIRMS separately — expected
  per-node semantics, not a missed vuln.

## LLM judgment layer (2026-07, first run)

`scripts/llm_judge_sink_chains.py` (pydantic-ai + DeepSeek `deepseek-v4-flash`,
PromptedOutput — thinking mode rejects forced `tool_choice`) judges every
sink→entrypoint chain from `extract_chain_snippets.sc` against
`ground_truth.json`. First full run, category-A recall (before the
`methodSource` fix — see the note in the category-B section):

- python 10/10, js 9/10, csharp 8/10, java 7/10 → **34/40 = 85%**
- Safe samples: 17/20 correctly rejected; the 3 FPs are all safe-XXE
  (py/java/js — model does not credit defusedxml / secure factory config /
  `noent:false`; csharp judged correctly).
- FN causes: java-sqli-02 / java-cmdi-02 / java-xss-01 — SIGNATURE-ONLY
  snippets from javasrc2cpg (model saw no method bodies; root cause found
  via the category-B path, fixed below); js-sqli-02 — NO_CHAIN (D5
  module-var gap); cs-cmdi-02 / cs-path-traversal-01 — NO_CHAIN (D7
  csharpsrc2cpg drops CALL edges into Services/).
- Category B stays 0/28: sink rules don't fire for non-sink classes
  (expected; needs the forward-analysis approach, not the LLM layer).

Re-run after porting the `methodSource` fix to `extract_chain_snippets.sc`
(same model, same sinks): **java 7/10 → 10/10**, java-safe-03 FP cleared
(model now sees the secure XML factory config) → **37/40 = 92.5%**,
safe-sample FPs down to 2/20 (py/js safe-XXE — a prompt-tuning issue, not
snippets). csharp 8/10 unchanged: its FNs are NO_CHAIN (D7), which snippet
quality cannot fix.

Re-run after the D5 ghost-callee repair (below): **js 9/10 → 10/10**
(js-sqli-02 now has chains: lookup → findStaged → db.query) →
**38/40 = 95%**. Only cs-cmdi-02 / cs-path-traversal-01 (D7) remain.

Re-run after the D7 text fallback (below): **csharp 8/10 → 10/10** →
**category A: 40/40 = 100%**, safe-sample FPs 2/20 (py/js safe-XXE —
prompt tuning, see backlog).

## Ground-truth label leak (2026-07, found & fixed)

The `VULN: id` / `SAFE: id` marker comments above each handler were
leaking into LLM prompts: pysrc2cpg and csharpsrc2cpg start the method
line range at the comment/attribute line, so the disk slice included the
marker (cs A 16/16 sinks, cs B 24/24, py B 15/24, py A 7 sinks; js/java
clean). Both judge scripts now strip marker lines in `build_prompt`
(`strip_gt_tags`). Clean re-runs (same snippets, same model):

- A: py 10/10, cs 10/10 — **unchanged, 40/40 = 100% stands**
- B: py 7/7 unchanged; **cs dropped 7/7 → 5/7** — cs-business-logic-01 and
  cs-race-condition-01 had genuinely relied on the label: the forward BFS
  missed `_orderService.Transfer(...)` nested in `Ok(...)` (the D7 gap in
  the FORWARD direction), so the model correctly answered "no evidence".
  Added the same text fallback (forward variant) to
  `extract_entrypoint_snippets.sc` → cs back to **7/7, now honestly**.
- Final clean totals: **A 40/40, B 28/28**; FPs py-safe-03, js-safe-03
  (XXE prompt), js-safe-05 (spinlock strictness).

## Category-B forward-analysis path (2026-07, built)

`analysis/joern/extract_entrypoint_snippets.sc` dumps every HTTP entrypoint
plus the source of its forward-reachable callees (BFS depth ≤ 5, ≤15
methods, JSONL per entrypoint); `scripts/llm_judge_entrypoints.py` asks the
LLM for a verdict on ALL 7 non-sink classes per endpoint and scores the
category-B entries of `ground_truth.json` (file+function match, route
fallback). Original `scripts/llm_judge.py` renamed to
`scripts/llm_judge_sink_chains.py` (category A). First full B run
(24 entrypoints/target, deepseek-v4-flash):

- python 7/7, java 7/7, csharp 7/7, js 7/7 → **28/28 = 100% recall**
- B safe samples: 7/8 correctly rejected. The 1 FP is js-safe-05 —
  the model calls the `while(locked); locked=true` spinlock a non-atomic
  check-then-set (conf 0.85); debatable but strict.
- Fixes that mattered: (1) js/ts handlers are anonymous `<lambda>N`, so
  scoring falls back to file+route and keeps only the MOST SPECIFIC
  suffix match — otherwise the vulnerable `GET /:id` record also matched
  the safe `GET /users/me/:id` entry and manufactured an FP; (2)
  javasrc2cpg fills method `code` with only the SIGNATURE line, so
  `methodSource` now prefers a disk slice whenever it is longer —
  without bodies the model answered "no implementation shown" on every
  java FN. The same signature-only flaw existed in
  `extract_chain_snippets.sc` (category-A path) — ported there too; see
  the re-run note in the section above.
- csharp recall holds despite D7 (missing CALL edges into Services/):
  the B-class flaws are visible in the controller bodies alone.

## Next up (do-later round, see DECISIONS.md)

1. ~~Jump-on-Field for JS module-level variables (D5)~~ — DONE (2026-07):
   the NO_CHAIN root cause was not dataflow but jssrc2cpg resolving
   require-imported calls (`userService.findStaged`) to GHOST methods in
   the caller's own file. Fixed with an import-binding call-edge repair in
   `backward_from_sinks.sc` / `extract_chain_snippets.sc` (a call site
   `recv.name(...)` with an external callee counts as a caller of the real
   method when `recv` is an import binding resolving to the method's
   file). js-sqli-02 10/10. The module-variable DATAFLOW gap in
   `taint_confirm.sc` remains open (LIMITATIONS §2).
2. Attach field/variable write sites to chain snippets (D6).
3. ~~Name-based call-site fallback for missing C# CALL edges (D7)~~ — DONE
   (2026-07): root cause was narrower than "dropped CALL edges" —
   csharpsrc2cpg drops the call NODE entirely when `_svc.Method(...)` is
   nested inside another call (`Ok(_svc.Method())`), so name-based call
   traversal finds nothing. Implemented a source-text fallback in
   `backward_from_sinks.sc` / `extract_chain_snippets.sc`: a controller
   method counts as a caller of service method `m` when its source contains
   `".<mname>("` AND its declaring type has a member of `m`'s declaring
   type. 10 LOW_CONFIDENCE edges synthesized, all semantically correct
   (safe variants map to safe methods, no false edges). cs A 8/10 → 10/10.
   The `taint_confirm.sc` DATAFLOW side of D7 remains open
   (LIMITATIONS §2).
