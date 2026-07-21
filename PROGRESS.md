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

## Next up (do-later round, see DECISIONS.md)

1. Jump-on-Field for JS module-level variables (D5).
2. Attach field/variable write sites to chain snippets (D6).
3. Name-based call-site fallback for missing C# CALL edges (D7, flagged
   LOW_CONFIDENCE).
