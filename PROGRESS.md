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

## Known gaps (details in LIMITATIONS.md)

- Source coverage: Flask path params (`/users/<int:user_id>`) not treated as
  sources; flows from `get_user` / `delete_user` missed.
- Sink matching: Semgrep line-hint off-by-one picked the wrong call for
  `java-ssti-01` (±1-line nearest-line tolerance).
- Joern OSS dataflow: JS module-level variables not tracked
  (`js-sqli-02`); C# cross-file flows lost past `Services/`
  (`cs-cmdi-02`, `cs-path-traversal-01`) — csharpsrc2cpg frontend limit.
- Structural: sanitizers invisible to dataflow (by design, LLM layer's job);
  backward chains miss the write side of field passing (`stage_name` store
  site absent from LLM snippets); forward script over-tags sinks by name;
  Semgrep name-based rules flag intermediate forwarding calls; JS flow
  attribution only works for direct route lambdas; flow output capped at 5
  with signature-based dedup crowding out distinct routes
  (`db/index.js:13`).

## Next up (agreed order, see DECISIONS.md)

1. Flask path parameters as taint sources.
2. Sink-name-first matching in `taint_confirm.sc`.
3. Chain-level confirmation report (join backward chains with confirm flows).
4. Flow dedup by (entrypoint x sink) + per-entry cap.

Then, in a later round:

5. Jump-on-Field for JS module-level variables.
6. Attach field/variable write sites to chain snippets.
7. Name-based call-site fallback for missing C# CALL edges (flagged
   LOW_CONFIDENCE).
