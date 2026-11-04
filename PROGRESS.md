# Progress

Status of the Semgrep + Joern taint-confirmation pipeline. Companion docs:
`analysis/LIMITATIONS.md` (known gaps), `DECISIONS.md` (what we decided to
do about them), `plan.md` (roadmap).

Only current-state entries live here; the M0–M8 execution log was pruned
on 2026-11-01 (recoverable from git history).

## Investigator path retired (2026-11-01) — gate PASS, D19

The tracer passed the frozen baseline gate end to end
(`run_baseline.py --compare workspace/agent-reports/2026-11-01-204727-trace/summary.json`):
A recall 10/10 on all three web targets (java-spring above its frozen 8/10),
0 new safe-sample FPs, GATE: PASS. Per the standing arrangement the
free-form investigator path was deleted the same day: `agent/run_agent.py`,
`sast_agent/investigator.py`, `tools.submit_finding`, and the
investigator-only budget `MAX_TOOL_CALLS_PER_SINK` are gone;
`run_trace.py` now owns the post-run tail (`finalize_target`) it previously
imported from run_agent. Retired docs: `docs/AGENT_MVP_PLAN.md` (closed
MVP spec), `agent/HANDOFF.md` (MVP handoff), `docs/agent-investigation-example-js-sqli-02.md`
(investigator walkthrough) — recoverable from git history. Verified after
the cut: no-LLM suite 91 passed, `run_trace.py --target canary-di --dry-run`
end to end.

## Non-HTTP targets at full A recall (2026-11-04) — scorer + rules fix

First LLM batch on the two registry-dispatch targets (2026-11-03) measured
judge-layer A recall 7/10 (java-fix-gateway) / 9/10 (python-clearing-worker).
Root causes and fixes: (1) `chain_matches_entry` (in
`agent/sast_agent/report.py` + `scripts/llm_judge_sink_chains.py`) rejected
same-sink verdicts under a different class label — it now falls back to an
exact positional match (same file, chain-terminal method == gt sink
function), which credits e.g. ScriptEngine eval logged as rce against a gt
ssti entry; (2) sink rules extended — java path-traversal adds
`FileWriter`/`FileOutputStream`, java/python xss add tag-literal `append`
assembly; (3) caveat recorded: `run_baseline.py` per-stage caching ignores
rule edits — rerun with `--force` and clear `workspace/agent-cache/<target>/`
before a tracer rerun. After the fixes: both targets 10/10 on judge and
tracer, 0 safe-sample FPs, gate PASS against the re-frozen `baseline.json`
(java-fix-gateway taint confirm 11/14, python-clearing-worker 5/16 —
pysrc2cpg dict/subscript DFG gap unchanged). No-LLM suite 91 passed.

## C# targets removed (2026-11-01) — D18

`targets/csharp-aspnet` and `targets/csharp-fix-gateway` are deleted (user
decision): `csharpsrc2cpg`'s x86_64 astgen cannot rebuild a CPG on this
arm64 host without Rosetta, so the C# numbers below are frozen history,
not reproducible results. `run_baseline.py` TARGETS now lists the five
engine-backed targets (three web stacks + the two registry-dispatch
securities targets; csharp entries were pruned from `baseline.json` on the
2026-11-03 re-freeze). Perl targets stay as the deliberate no-engine tier-3
degraded-mode cases.

## A-class tracer: state-machine redesign (2026-11-01) — M9 landed

The A-class (sink-based taint) investigation path is rebuilt from the
free-form investigator playbook into a **state machine**: the Python
orchestrator owns a per-sink `TraceState` dossier, the LLM answers ONE
`PromptedOutput(TraceStep)` per round (resolve last round's candidates,
judge completeness, issue at most one directive from a closed menu), and
the orchestrator executes every engine step itself (`trace_step.sc`, one
JVM per directive; `read_file`/`search_code` delegate to the red-lined
SastTools). No tool-calling LLM, no joern syntax in prompts, no
full-history replay. New modules: `trace_schema.py` / `trace_engine.py` /
`trace_prompts.py` / `tracer.py`, CLI `run_trace.py`, 24 new no-LLM tests
(suite now 91). The investigator path stayed until the gate passed — see
"Investigator path retired" above.

- **Anti-hallucination bottom line (M9.4).** Every `llm_inferred` hop
  carries a `justify_ref: "file:start-end"`; it is pre-checked when the
  hop enters the chain and re-checked by `report.validate_finding`
  (CONFIRMED → LIKELY downgrade on failure).
- **Guardrails bought by the canary.** `workspace/canary-di/` (registry
  dynamic dispatch + module-variable staging) drove two mechanical
  rules: DEAD is rejected until a broad-recall probe
  (find_call_sites/search_code) has been tried, and `callers_of` falls
  back to identifier reference sites so registry-value functions resolve.
  Canary verdict: COMPLETE via writes_to → callers_of → reads_of →
  find_call_sites, TP.
- **Multi-chain verdicts.** Full-run v1 exposed the class: a sink
  reachable from several entrypoints was judged on the seeded-longest
  chain only, so a sanitizer on ONE route (Flask `<int:id>` converter,
  an allow-list wrapper) vetoed the whole sink (py-sqli-01/02,
  java-path-traversal-01 FNs). Fix: the verdict envelope lists every
  engine chain with a judge-each-chain rule, and a vulnerable verdict
  carries `exploitable_chain` (index) that re-anchors the finding — and
  therefore the verifier — to the exploitable chain. (v2: py/java/js
  back to 10/10.)
- **Repeat-directive redirect.** The v2 full run died on a case reading the
  same file 3× without ever trying `writes_to` on the staging field. The
  no-progress detector now rejects the 2nd identical directive with a
  redirect naming the untried avenues (DEAD only on the 3rd), and the
  step prompt gained the parameterless-frontier rule (taint staged in
  `this.field`/`self.field`/module globals arrives via a WRITE — issue
  `writes_to(field)`, don't conclude "never passed in").
- **Full-run numbers (v3 batch, verifier on):** A-class recall 10/10 on
  all four targets (the fourth was the since-removed C# target), 0
  safe-sample FPs, baseline gate PASS
  (`workspace/agent-reports/2026-11-01-160937-trace/summary.json`).
  java-spring improved over the frozen judge baseline (10/10 vs 8/10).
  Token spend 0.57M/0.64M/0.72M/0.92M (py/java/js/cs, ~2.85M total) —
  same ballpark as the investigator for now because the adversarial
  verifier dominates; the trace calls themselves are an order of
  magnitude cheaper (single-sink: 7.3k tokens clean chain, ~27k for a
  4–8 directive continuation, vs dozens of tool round-trips before).
- **Housekeeping:** `python-flask-enterprise` was user-deleted in D17
  (9947ba2) but still registered in `config.py` / `run_baseline.py`
  TARGETS, breaking every `--target all`; removed. The C# targets'
  CPGs could not be rebuilt on this arm64 host (Rosetta missing, astgen
  is x86_64 — a re-parse silently yields a 0-method CPG); both targets
  were removed the same day (D18) rather than kept as unreproducible
  history (see LIMITATIONS.md §3).
- **M9.0 note:** the planned joern prelude commonization is not possible
  as designed (`--script` replpp does not support `import $file`);
  delivered as M9.0-lite — the snippets sink-matching block was aligned
  to backward_from_sinks' ±3 window + kind ranking, drift now covered by
  the gate's snippet hash.
