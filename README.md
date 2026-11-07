# SAST Benchmark Targets (Semgrep + Joern + LLM)

Intentionally vulnerable, simplified projects in four language stacks —
built to evaluate an **LLM + Semgrep + Joern** SAST pipeline for
**category A (sink-based)** vulnerabilities: Semgrep finds sink call
sites; Joern traces taint backward from each sink to its entrypoint.

> ⚠️ **DO NOT deploy or run this code.** Every vulnerability is deliberate.
> The projects are *source-only*: they are meant to be parsed by Semgrep and
> Joern, not compiled or executed. Imported frameworks are not installed.

## Layout

```
targets/
├── java-spring/        Java + Spring Boot style (@RestController)
├── js-ts-express/      Express 4, mixed .js and .ts
├── python-flask/       Python + Flask (blueprints)
├── perl-cgi/           Legacy CGI.pm-style Perl (no engine support by design)
├── java-fix-gateway/   Non-HTTP: FIX-style TCP order gateway (registry dispatch)
└── python-clearing-worker/  Non-HTTP: clearing/reconciliation message+file worker
```

(The legacy JSP target `jsp-legacy/` was removed on 2026-09-05, the
`python-flask-enterprise` / `php-laravel` pilots later, and both C# targets
(`csharp-aspnet`, `csharp-fix-gateway`) on 2026-11-01 — csharpsrc2cpg cannot
rebuild a CPG on this arm64 host, so they are out of the benchmark; all live
on in git history if ever needed again.)

Each HTTP project contains `routes|controllers/` (entrypoints), `services/`
(business logic), `data|db/` (data access sinks), `config/` (hardcoded
secrets), plus **`ground_truth.json`** (machine-readable scoring baseline) and
**`GROUND_TRUTH.md`** (human-readable table). The non-HTTP projects mirror the
same layering with protocol/registry dispatch instead of HTTP routes (see
DECISIONS.md D17). Since D15 no project carries in-source `VULN:`/`SAFE:`
markers — ground truth is the only record (anti-overfitting).

Note: the ground truth still records category-B (non-sink) entries for
future B-class detection work; the current pipeline consumes category A
only.

## Vulnerability matrix (category A)

The sink idioms below are the HTTP targets'; the non-HTTP targets use their
own per-language idioms (e.g. `pickle.loads`, `ScriptEngine.eval`) listed
in each `GROUND_TRUTH.md`.

| Type | CWE | Java | JS/TS | Python |
|------|-----|------|-------|--------|
| SQL Injection | 89 | `Statement.executeQuery` concat | `mysql.query` concat | `cursor.execute` f-string |
| XSS | 79 | HTML concat response | `res.send` concat | HTML concat response |
| Command Injection | 78 | `Runtime.exec` | `child_process.exec` | `os.system` |
| Path Traversal | 22 | `Files.readAllBytes` | `fs.readFileSync` | `open(base+name)` |
| RCE (code eval) | 94 | `ScriptEngine.eval` | `eval()` | `eval()` |
| XXE | 611 | `DocumentBuilderFactory` (DTD on) | `libxmljs noent:true` | lxml `resolve_entities=True` |
| Deserialization | 502 | `ObjectInputStream.readObject` | `node-serialize.unserialize` | `pickle.loads` |
| SSTI | 1336 | Freemarker `new Template` | `ejs.render` | `render_template_string` |

### Difficulty mix

- **shallow** — sink inside the entrypoint handler itself.
- **medium** — entrypoint → service → data/util (2-3 files).
- **deep** — 3+ file chain with taint passed through an instance/module
  *field* (SQLi, command injection; field-sensitive analysis required).

### Negative samples (5 per project)

Look-alike but safe code near the real vulnerabilities, for measuring false
positives: parameterized query, ownership-checked endpoint, DTD-disabled XML
parser, allow-listed file download, lock-protected withdrawal. Marked
`"expected": "safe"` in the ground truth.

## Ground truth format

`ground_truth.json` is a JSON array; see any project for examples. Vulnerable
entries carry `id`, `category` (A/B), `vuln_type`, `cwe`, `expected:
"vulnerable"`, `difficulty`, `entrypoint {route,file,function}`, `sink`
(A only), `chain` (ordered files) and `notes`. Safe entries set
`expected: "safe"` and omit `sink`/`chain`/`difficulty`.

## Quick start

```bash
# Semgrep (per target)
semgrep --config=auto targets/python-flask
semgrep --config=auto --json --output=semgrep_py.json targets/python-flask

# Joern: build a CPG per target (binaries are gitignored)
joern-parse targets/python-flask --output py_cpg.bin
joern-parse targets/java-spring --output java_cpg.bin
joern-parse targets/js-ts-express --output js_cpg.bin

# then explore, e.g.
joern --script your_script.sc   # with the CPG imported
```

## Analysis helpers (ready-made Semgrep → Joern workflow)

The `analysis/` and `scripts/` directories implement the two-step pipeline:

```bash
# 0. One-time: build the CPG for a target
joern-parse targets/python-flask --output py_cpg.bin

# 1a. Semgrep: find sinks with the bundled per-language rules, save to JSON
semgrep --config analysis/rules/sinks-python.yml --json -o /tmp/raw_py.json targets/python-flask

# 1b. Convert to the compact sink list the Joern script understands
python3 scripts/semgrep_to_sinks.py /tmp/raw_py.json --root targets/python-flask -o /tmp/sinks_py.json

# 2. Joern backward trace: sink -> caller -> ... -> entrypoint
SINKS_FILE=/tmp/sinks_py.json joern --script analysis/joern/backward_from_sinks.sc py_cpg.bin
#    (omit SINKS_FILE to enumerate sinks from the CPG's built-in name table instead)

# 3. Extract source snippets for every sink chain (JSON lines, LLM-ready)
SINKS_FILE=/tmp/sinks_py.json joern --script analysis/joern/extract_chain_snippets.sc py_cpg.bin > /tmp/snippets_py.jsonl

# 4. Dataflow confirmation: does request input actually reach each sink argument?
SINKS_FILE=/tmp/sinks_py.json joern --script analysis/joern/taint_confirm.sc py_cpg.bin > /tmp/taint_py.jsonl

# 5. LLM judgment (category A): is each sink->entrypoint chain a real vulnerability?
#    (DeepSeek via pydantic-ai; needs DEEPSEEK_API_KEY in env or .env)
uv run scripts/llm_judge_sink_chains.py --snippets /tmp/snippets_py.jsonl \
    --ground-truth targets/python-flask/ground_truth.json -o /tmp/verdicts_py.jsonl
```

Files:

| Path | Purpose |
| ---- | ------- |
| `analysis/rules/sinks-{python,java,js}.yml` | Semgrep sink rules, 8 category-A classes per language |
| `scripts/semgrep_to_sinks.py` | Semgrep JSON → compact sink list (`file`/`line`/`rule`/`vuln_type`) |
| `analysis/joern/backward_from_sinks.sc` | Reverse call-chain walk from each sink to an entrypoint |
| `analysis/joern/extract_chain_snippets.sc` | Dumps source code of every method on each sink→entrypoint chain (JSON lines; set `SRC_ROOT` to the parse root when the frontend leaves method `code` empty) |
| `analysis/joern/taint_confirm.sc` | Dataflow confirmation: `sink.argument.reachableByFlows(request.* sources)` per Semgrep sink; JSON lines with `CONFIRMED`/`UNCONFIRMED` + flow paths |
| `scripts/llm_judge_sink_chains.py` | LLM judgment layer, category A (pydantic-ai + DeepSeek): synthesizes each sink→entrypoint chain's snippets into a prompt, returns a structured verdict, and scores recall/FP against `ground_truth.json` (`--from-verdicts` re-scores without re-calling the LLM) |

The same commands work for the other targets — swap the rules file
(`sinks-java.yml`, `sinks-js.yml`) and the CPG.

## Autonomous investigation agent (`agent/`)

The `agent/` directory turns the fixed pipeline above into a **pydantic-ai
investigation agent**. The **tracer state machine** owns a per-sink
`TraceState` dossier and executes every engine step itself
(`trace_engine.py`, one Joern JVM per directive), while the LLM answers ONE
structured `TraceStep` per round — resolve candidates, judge completeness,
issue at most one directive from a closed menu (`callers_of` / `writes_to` /
`reads_of` / `find_call_sites` / `trace_back` / `methods_in_file` /
`read_file` / `search_code`). The LLM never touches Joern syntax, and every
LLM-inferred hop must carry a disk-checkable `justify_ref`. Every vulnerable
verdict passes an attacker/defender adversarial review (`verifier.py`)
before it reaches the report.

```bash
# category A, one target (reports -> workspace/agent-reports/<target>-trace/)
uv run --offline agent/run_trace.py --target python-flask

# category A, all registered targets, parallelism 2
# (reports -> workspace/agent-reports/<date>-trace/)
uv run --offline agent/run_trace.py --target all

# regression gate against the frozen baseline: non-zero exit when
# category-A recall drops or a new safe-sample FP appears
python3 agent/run_baseline.py --compare
```

Status: category-A recall 11/11 (python-flask), 12/12 (java-spring,
js-ts-express), 10/10 (java-fix-gateway, python-clearing-worker) via the
tracer, 0 safe-sample FPs, baseline gate PASS. The old free-form
investigator path was retired after the tracer passed the gate
(DECISIONS.md D19). Details: `PROGRESS.md`; roadmap: `plan.md`.

## Notes

- The C# targets (`csharp-aspnet`, `csharp-fix-gateway`) were removed on
  2026-11-01: `csharpsrc2cpg`'s astgen is x86_64 and this arm64 host has no
  Rosetta, so their CPGs can no longer be rebuilt (LIMITATIONS.md §3). They
  live on in git history.
- `js-ts-express` mixes `.js` and `.ts`; filter by extension for per-language
  scoring.
- Dataflow confirmation (`taint_confirm.sc`) verified results per language:
  - **python**: 12/12 Semgrep sinks CONFIRMED, incl. both field-passing deep
    chains; hardcoded-SQL fake chain correctly excluded.
  - **java**: 10/11 CONFIRMED via `@RequestParam`/`@RequestBody` parameter
    sources; `java-ssti-01` missed (Semgrep line hint points at the
    `new Configuration(...)` line, one off from the tainted `new Template`).
  - **js/ts**: most sinks CONFIRMED with route-attributed sources; the
    module-level field chain (`js-sqli-02`, `pendingName`) is NOT tracked by
    OSS dataflow across files — instance-field chains (java/python)
    are tracked, module-scope variables are not.
