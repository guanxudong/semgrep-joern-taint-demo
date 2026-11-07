# Agent Guidance: SAST Benchmark Targets

This repository contains **intentionally vulnerable** test-target projects used
to benchmark an LLM + Semgrep + Joern SAST pipeline for **category A
(sink-based)** vulnerabilities.

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
- `targets/perl-cgi/` — legacy CGI.pm-style Perl (source only, 2026-09-26):
  one `.pl` script per action under `cgi-bin/` (routes are the script paths
  by filename convention, e.g. `cgi-bin/users/search.pl` →
  `/users/search.pl`), plain-OO services under `lib/MyApp/`. **Neither
  Semgrep nor Joern supports Perl** — a tier-3 target for the no-engine
  degraded mode (design: `docs/perl-degraded-mode-design.md`, DECISIONS.md
  D10/D15). Not yet registered in the agent pipeline.
- Non-HTTP securities-industry targets (2026-10-31, DECISIONS.md D17;
  registered in the pipeline 2026-11-01; language↔scenario paired by
  industry reality, NOT one per language):
  - `targets/java-fix-gateway` — FIX-style TCP order gateway (registry
    dispatch on MsgType, custom text protocol). (Its C# mirror
    `csharp-fix-gateway` was removed on 2026-11-01 with `csharp-aspnet`:
    csharpsrc2cpg cannot rebuild a CPG on this arm64 host.)
  - `targets/python-clearing-worker` — clearing/reconciliation pipeline
    consuming execution-report messages and settlement file drops
    (its Perl mirror was removed on 2026-11-01 as redundant).
  - In these targets `ground_truth.json`'s `entrypoint.route` carries a
    **trigger descriptor** (`MSG <subject>` / `CMD <command>` /
    `FILE <kind>`) instead of an HTTP route. **Message/file/command
    dispatch must always be written registry-shaped**
    (`router.register("D", fn)` / `HANDLERS["D"] = fn` /
    `subscribe(subject, fn)`) — never a switch — so Joern can see the
    entrypoints. External dependencies are in-repo stubs or the language
    standard library (source-only constraint).
- **No target carries in-source ground-truth markers.** Since 2026-09-26
  (DECISIONS.md D15) the `VULN:`/`SAFE:` comment convention is retired
  everywhere, and source comments must never reveal a vulnerability's
  presence, class, or dataflow role — the LLM reads the source, so
  `ground_truth.json` + `GROUND_TRUTH.md` are the only record
  (anti-overfitting; the enterprise pilot started this as D11).
- Each target has `ground_truth.json` + `GROUND_TRUTH.md` (kept in sync).
  The ground truth still records category-B (non-sink) entries for future
  B-class detection work; the current pipeline consumes category A only.
  (The fifth target `targets/jsp-legacy/` and its transpiler
  `scripts/jsp_to_java.py` were removed on 2026-09-05 by user decision —
  recoverable from git history.)
- `analysis/rules/` — Semgrep sink rules per language (8 category-A classes).
- `analysis/joern/` — Joern scripts: sink→entrypoint backward trace
  (JSONL side output via `CHAINS_JSON`, plus a `dead_end` record per
  no-chain sink naming the stall method and its unresolved calls), chain
  source-snippet extraction (`extract_chain_snippets.sc`; set `SRC_ROOT` to
  the parse root), dataflow taint confirmation (`taint_confirm.sc`),
  single-directive trace step for the tracer (`trace_step.sc`; set
  `DIRECTIVE_FILE` to a JSON directive, one JVM per directive; `callers_of`
  falls back to identifier reference sites so registry-value functions
  resolve).
- `analysis/LIMITATIONS.md` — known gaps: §§1–3 the factual engine/pipeline
  record (source coverage, dataflow-engine limits, pipeline issues;
  engine-side work dropped 2026-09-10), §4 the live agent/LLM-layer
  backlog, §5 the pruned engine ideas backlog (empty; roadmap pointer to
  plan.md). Read this first when resuming analysis work in a new session.
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
- `agent/` — investigation agent (post-MVP; the original M0–M8 MVP spec and
  handoff were retired with the investigator path on 2026-11-01, D19):
  `sast_agent/` package (config/contracts/pipeline/scrub/tools/report +
  tracer + verifier), CLI `run_trace.py` (category A),
  `run_baseline.py` (baseline freezer; `--compare` = regression gate
  against `workspace/baseline/baseline.json` (v2: `{version, provenance,
  targets}`); verdicts PASS/SKIP/FAIL where SKIP = "not comparable" and
  never fails unless `--require-baseline`; every FAIL names its cause —
  MODEL_DRIFT / CODE_CHANGED / SNIPPET_CHANGED / ENGINE_CHANGED /
  JUDGE_CHANGED, else REAL_REGRESSION — and optional dimensions
  `--max-token-delta PCT` (vs the previous batch),
  `--min-confirmed-rate PCT`, `--forbid-leak`), smoke scripts
  (`smoke_tools.py`, `smoke_verifier.py`). Same DeepSeek env as the LLM
  judge. Agent tools must never read `ground_truth.json` /
  `GROUND_TRUTH.md` (hard-refused) nor write under `targets/`.
  - **Tracer path (category A, state-machine design)**: `trace_schema.py`
    (Hop/Candidate/TraceDirective/TraceStep/TraceState — the LLM fills one
    `TraceStep` per round via `PromptedOutput`, no tools, directives from a
    closed enum menu), `trace_engine.py` (executes directives: joern ones
    via `trace_step.sc`, `read_file`/`search_code` delegate to `SastTools`
    so the red lines + scrubber still apply), `trace_prompts.py` (step/
    verdict instructions), `tracer.py` (`trace_sink` loop: envelope = chain
    dossier + frontier source + candidates + taint facts; guardrails: DEAD
    refused until find_call_sites/search_code tried, no-progress detector,
    budget `MAX_TRACE_STEPS_PER_SINK=12`; every `llm_inferred` hop needs a
    `justify_ref: "file:start-end"` that must resolve to the named
    identifier or the verdict is downgraded; multi-chain sinks are judged
    chain-by-chain — the verdict envelope lists every engine chain and a
    vulnerable verdict carries `exploitable_chain` (1-based index) so the
    finding/verifier anchors to the exploitable chain, not the
    seeded-longest one), CLI `run_trace.py`
    (`uv run --offline agent/run_trace.py --target <name|all|canary-di>
    [--limit N] [--only-sink X] [--no-verify] [--dry-run]`, reports under
    `workspace/agent-reports/<date>-trace/`). The canary target
    `workspace/canary-di/` (registry dynamic dispatch + module-var store,
    one canary-cmdi-01) exists only to prove hop-by-hop continuation.
    Passed the baseline gate 2026-11-01 (10/10 on all three web targets,
    0 new safe FPs); the old free-form investigator path was deleted the
    same day.
- `agent/sast_agent/scrub.py` — the **single** ground-truth scrubber
  (red line, DECISIONS.md D16). `strip_gt_tags()` removes every known
  marker shape; `scrub()` strips then ASSERTS nothing label-shaped survived
  — certain hit → appended to `workspace/leak-audit.jsonl` and
  `GroundTruthLeak` raised (the run fails); suspected (a bare
  `<lang>-<type>-<nn>` id) → audited only. Never reads ground truth: the id
  shape is a hardcoded regex. Wired into `SastTools.read_function` /
  `search_code` / `get_chain_snippets` (covers tracer + verifier) and the
  judge's `build_prompt`; the judge also accepts `--check-leak` to build
  every prompt and assert offline (no API key). Fixtures for the shapes:
  `tests/fixtures/leak/` (the targets themselves are marker-free since D15
  and cannot serve as fixtures).
- `tests/` — no-LLM test suite: `uv run --with pytest --with pydantic
  --with "pydantic-ai-slim[openai]>=2.0.0" --with python-dotenv pytest
  tests -q`
  (scrubber + regression gate + tracer state machine, including the gate's
  self-tests on fabricated summaries; `test_ground_truth.py` structurally
  validates every target's `ground_truth.json` against its source — file/
  function existence, framework route/trigger registration, cat-A sink+chain
  resolution, cwe↔vuln_type map, and GROUND_TRUTH.md↔JSON id sync). No API
  key, no joern, no CPG needed. Anything that can be checked without an LLM
  belongs here rather than in a smoke script.

## Vulnerability taxonomy

Category A per project: 8 sink-based classes (sqli, xss, cmdi,
path-traversal, rce, xxe, deserialization, ssti), plus 5 negative samples.
The ground truth additionally records 7 non-sink category-B classes (idor,
business-logic, race-condition, priv-esc, mass-assignment,
broken-access-control, auth-flaws) for future B-class detection work; the
current pipeline (rules, Joern scripts, tracer, LLM judge, regression gate)
consumes category A only.

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

- **Repo code (always, no LLM):** `uv run --with pytest --with pydantic
  --with "pydantic-ai-slim[openai]>=2.0.0" --with python-dotenv pytest
  tests -q`
  and `python3 agent/run_baseline.py --compare <summary.json>`. A change to
  a prompt, a tool, the scrubber or the gate must keep the suite green;
  `--compare` is the only gate that sees LLM verdicts.
- **Leak check (no LLM):** `uv run scripts/llm_judge_sink_chains.py
  --check-leak --snippets <snips.jsonl> --ground-truth targets/<t>/ground_truth.json`
  Runs in CI/without an API key; non-zero exit on a leak.
- **LLM runs on this host:** httpx reads the macOS *system* proxy bypass
  list when no proxy env var is set, and chokes on IPv6 bypass entries
  (`httpx.InvalidURL: Invalid port: ':1]'` from a `::1`/`[::1]` bypass
  entry). Launch LLM stages with a clean override, e.g.
  `env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY -u all_proxy no_proxy=localhost,127.0.0.1 NO_PROXY=localhost,127.0.0.1 python3 agent/run_baseline.py ...`
  (env `no_proxy` shadows the system bypass list; DeepSeek is reached
  directly, no proxy needed).
- Python: `python3 -m py_compile` all `.py` in the target.
- JS: `node --check` all `.js` in the target (TS is verified via joern-parse).
- PHP: `php -l` all `.php` if a PHP runtime is installed; otherwise a
  `semgrep targets/php-laravel` parse check suffices.
- Perl: `perl -c -Ilib` per file; `Can't locate ... in @INC` (uninstalled
  CPAN modules) is acceptable, syntax errors are not.
- All: `python3 -m json.tool` on each `ground_truth.json`.
- Parse check: `joern-parse targets/<name> --output /tmp/<name>.cpg.bin` must
  succeed; `semgrep targets/<name>` must run without parse errors —
  **except the Perl target** (`perl-cgi`), which neither engine supports by
  design (that is what the tier-3 degraded mode tests). The C# targets were
  removed on 2026-11-01 for the opposite reason:
  `csharpsrc2cpg`'s astgen is x86_64, and on this arm64 Mac without Rosetta
  joern-parse silently yields a 0-method empty CPG — verify method count,
  never trust an empty parse (see LIMITATIONS.md §3).
