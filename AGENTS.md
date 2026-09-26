# Agent Guidance: SAST Benchmark Targets

This repository contains **intentionally vulnerable** test-target projects used
to benchmark an LLM + Semgrep + Joern SAST pipeline.

## Core constraints

- **Do not fix the vulnerabilities.** Every weakness is deliberate and serves
  the benchmark. This also applies to the **negative samples** (`SAFE:`
  entries) — they are already safe on purpose; do not "harden" anything else,
  and do not convert a vulnerable entry into a safe one or vice versa.
- **Source-only projects.** The targets are parsed by Semgrep/Joern, never
  compiled or run. Do not add build files (`pom.xml`, `package.json`,
  `*.csproj`, `pyproject.toml`) unless the user explicitly asks.
- **Do not commit generated artifacts.** CPGs (`*.cpg.bin`, `*.bin`,
  `workspace/`) and Semgrep outputs (`semgrep_*.json`) are gitignored and must
  be regenerated locally.

## Layout

- `targets/java-spring/` — Spring Boot style (source only)
- `targets/js-ts-express/` — Express, mixed .js/.ts (source only)
- `targets/python-flask/` — Flask blueprints (source only)
- `targets/csharp-aspnet/` — ASP.NET Core style (source only)
- `targets/python-flask-enterprise/` — enterprise-style pilot ("OrderFlow"
  B2B order/inventory API, 2026-09-15): layered `api/` blueprints →
  `services/` → `repositories/` → `data/`, auth decorators, middleware,
  ~50 endpoints, 19 vulns + 11 safe mimics.
- `targets/php-laravel/` — Laravel-style PHP (source only, 2026-09-26).
  Engines: Semgrep GA + Joern php2cpg (needs a PHP runtime; less mature) —
  a tier-1 target for testing the full pipeline on a weaker frontend
  (DECISIONS.md D15). Not yet registered in the agent pipeline.
- `targets/perl-mojo/` — Mojolicious-style Perl (source only, 2026-09-26).
  **Neither Semgrep nor Joern supports Perl** — a tier-3 target for the
  no-engine degraded mode (design: `docs/perl-degraded-mode-design.md`,
  DECISIONS.md D10/D15). Not yet registered in the agent pipeline.
- **No target carries in-source ground-truth markers.** Since 2026-09-26
  (DECISIONS.md D15) the `VULN:`/`SAFE:` comment convention is retired
  everywhere, and source comments must never reveal a vulnerability's
  presence, class, or dataflow role — the LLM reads the source, so
  `ground_truth.json` + `GROUND_TRUTH.md` are the only record
  (anti-overfitting; the enterprise pilot started this as D11).
- Each target has `ground_truth.json` + `GROUND_TRUTH.md` (kept in sync).
  (The fifth target `targets/jsp-legacy/` and its transpiler
  `scripts/jsp_to_java.py` were removed on 2026-09-05 by user decision —
  recoverable from git history.)
- `analysis/rules/` — Semgrep sink rules per language (8 category-A classes).
- `analysis/joern/` — Joern scripts: entrypoint enumeration, sink→entrypoint
  backward trace (JSONL side output via `CHAINS_JSON`), entrypoint→down
  forward trace, chain source-snippet extraction
  (`extract_chain_snippets.sc`; set `SRC_ROOT` to the parse root),
  entrypoint+forward-reachable source-snippet extraction
  (`extract_entrypoint_snippets.sc`), dataflow taint confirmation
  (`taint_confirm.sc`), CPG-derived repo map (`repo_map.sc`; prints one JSON
  object on stdout — joern logs go to stdout too, so pipe through
  `awk '/^\{$/,/^\}$/'`).
- `analysis/LIMITATIONS.md` — known gaps: §§1–3 the factual engine/pipeline
  record (source coverage, dataflow-engine limits, pipeline issues;
  engine-side work dropped 2026-09-10), §4 the live agent/LLM-layer
  backlog (model drift, safe-02 FP, verifier asymmetry, budget truncation,
  hardcoded coverage assumptions, enterprise validation gap), §5 the
  pruned engine ideas backlog (empty; roadmap pointer to plan.md). Read
  this first when resuming analysis work in a new session.
- `plan.md` (repo root) — roadmap, re-sequenced 2026-09-23 (D14): Phase 1 =
  AI SAST agent productization (M14.1 orchestrator → M14.3 enterprise
  validation → M14.2 tri-state judge + model tiering → M9 → M11);
  Phase 2 = deferred self-evolution (M10 rules, M12 loop, M13.1 canary);
  plus unscheduled items.
- `PROGRESS.md` / `DECISIONS.md` (repo root) — pipeline status/next
  steps, and the optimization decisions (do-now / do-later / deferred) taken
  against those limitations.
- `scripts/semgrep_to_sinks.py` — converts Semgrep JSON into the sink list
  consumed by `backward_from_sinks.sc` (via `SINKS_FILE`).
- `scripts/chain_report.py` — joins the `CHAINS_JSON` chains with the
  `taint_confirm.sc` JSONL into a per-chain CONFIRMED/UNCONFIRMED report.
- `scripts/llm_judge_sink_chains.py` — LLM judgment layer for category A
  (pydantic-ai + DeepSeek, OpenAI-compatible endpoint; env
  `DEEPSEEK_API_KEY`/`DEEPSEEK_MODEL`/`DEEPSEEK_BASE_URL`, falls back to
  `~/Code/agent-demo/.env`). Judges each sink→entrypoint chain from
  `extract_chain_snippets.sc` output and scores recall / safe-sample FPs
  against `ground_truth.json`. Run with `uv run` (PEP 723 deps inline);
  `--from-verdicts` re-scores a saved verdicts JSONL without new LLM calls.
- `scripts/llm_judge_entrypoints.py` — LLM judgment layer for category B
  (same DeepSeek setup). Judges each HTTP entrypoint from
  `extract_entrypoint_snippets.sc` output (handler + forward-reachable
  callee source) semantically against all 7 non-sink classes, then scores
  the category-B entries of `ground_truth.json` (matching on file+function,
  route as fallback). Same CLI shape as `llm_judge_sink_chains.py`.
- `scripts/repo_map.py` — repo-map generator (tree-sitter, `uv run`, PEP
  723 deps inline; Java/JS/TS/Python/C#). Emits an LLM-consumable Markdown
  map (directory tree + roles, HTTP route table for Flask/Express/Spring/
  ASP.NET, per-file symbols, import-level reference graph) plus a JSON twin.
  `--check ground_truth.json` cross-checks extracted routes/functions.
  This is the default mapper for unknown repos (zero prerequisites); see
  `analysis/repo_map_compare.md` for the tree-sitter vs Joern comparison.
- `scripts/compare_repo_maps.py` — scores one or more repo-map JSONs
  (tree-sitter or joern schema) against a `ground_truth.json`: route and
  function hit rates plus coverage stats.
- `agent/` — MVP investigation agent (spec `docs/AGENT_MVP_PLAN.md`,
  closed M0–M8; handoff `agent/HANDOFF.md`): `sast_agent/` package (config/contracts/pipeline/
  tools/investigator/verifier/report/planner/worker), CLI `run_agent.py` (`uv run
  --offline agent/run_agent.py --target <name|all>`; `all` = batch mode,
  parallelism 2, reports under `workspace/agent-reports/<date>/`),
  `run_baseline.py` (M0 baseline freezer; `--compare` = regression gate
  against `workspace/baseline/baseline.json`, auto-detects A-class
  `summary.json` vs B-class `summary_b.json`), `run_planner.py` (M6
  category-B planner: hypothesis queue per target to
  `workspace/agent-cache/<target>/hypotheses.jsonl` + post-run ground-truth
  route-coverage check; M8: also emits a per-class taxonomy coverage
  checklist to `taxonomy_checklist.json`, rendered into `report_b.md`'s
  audit section), `run_worker.py` (M7 category-B worker: consumes
  the hypothesis queue, absence-comparison investigation + adversarial
  review, reports under `workspace/agent-reports/<date>-m7/<target>/`),
  smoke scripts
  (`smoke_tools.py`, `smoke_verifier.py`, `smoke_m8.py`). Same DeepSeek env
  as the LLM judges. Agent tools must never read `ground_truth.json` /
  `GROUND_TRUTH.md` (hard-refused) nor write under `targets/`.

## Vulnerability taxonomy

15 classes per project: 8 sink-based category A (sqli, xss, cmdi,
path-traversal, rce, xxe, deserialization, ssti) and 7 non-sink category B
(idor, business-logic, race-condition, priv-esc, mass-assignment,
broken-access-control, auth-flaws), plus 5 negative samples.

## Changing the targets

When adding/modifying a vulnerability:

1. **Never** put `VULN:`/`SAFE:` markers or any comment that hints at a
   vulnerability's presence, class, mechanism, or dataflow role in the
   source — the LLM reads the source, so comments must be neutral and
   functional only (DECISIONS.md D15). Identifiers are referenced by the
   ground truth, so rename them only together with the ground truth.
2. Update **both** `ground_truth.json` and `GROUND_TRUTH.md` in that project —
   ids, routes, functions, sink, chain must match the code exactly.
3. Mirror the change across the other projects if it is a taxonomic
   change (same `vuln_type` set everywhere).
4. Validate: `python3 -m json.tool <project>/ground_truth.json` and, for
   Python files, `python3 -m py_compile`.

## Testing changes

- Python: `python3 -m py_compile` all `.py` in the target.
- JS: `node --check` all `.js` in the target (TS is verified via joern-parse).
- PHP: `php -l` all `.php` if a PHP runtime is installed; otherwise a
  `semgrep targets/php-laravel` parse check suffices.
- Perl: `perl -c -Ilib` per file; `Can't locate ... in @INC` (uninstalled
  CPAN modules) is acceptable, syntax errors are not.
- All: `python3 -m json.tool` on each `ground_truth.json`.
- Parse check: `joern-parse targets/<name> --output /tmp/<name>.cpg.bin` must
  succeed; `semgrep targets/<name>` must run without parse errors —
  **except `perl-mojo`**, which neither engine supports by design (that is
  what the target tests).
