# SAST Benchmark Targets (Semgrep + Joern + LLM)

Intentionally vulnerable, simplified web projects in four language stacks, built
to evaluate an **LLM + Semgrep + Joern** SAST pipeline:

1. **Category A (sink-based)** — Semgrep finds sink call sites; Joern traces
   taint backward from each sink to its HTTP entrypoint.
2. **Category B (non-sink)** — Joern identifies entrypoints and reasons forward
   down the call chain for business-logic flaws.

> ⚠️ **DO NOT deploy or run this code.** Every vulnerability is deliberate.
> The projects are *source-only*: they are meant to be parsed by Semgrep and
> Joern, not compiled or executed. Imported frameworks are not installed.

## Layout

```
targets/
├── java-spring/        Java + Spring Boot style (@RestController)
├── js-ts-express/      Express 4, mixed .js and .ts
├── python-flask/       Python + Flask (blueprints)
└── csharp-aspnet/      C# + ASP.NET Core style controllers
```

Each project contains `routes|controllers/` (entrypoints), `services/`
(business logic), `data|db/` (data access sinks), `config/` (hardcoded
secrets), plus **`ground_truth.json`** (machine-readable scoring baseline) and
**`GROUND_TRUTH.md`** (human-readable table). Every vulnerable handler carries
a `VULN: <id>` comment matching its ground-truth id; safe counter-examples
carry `SAFE: <id>`.

## Vulnerability matrix (per project: 17 vulnerable entries + 5 safe)

### Category A — sink-based (Semgrep → sink, Joern → entrypoint)

| Type | CWE | Java | JS/TS | Python | C# |
|------|-----|------|-------|--------|-----|
| SQL Injection | 89 | `Statement.executeQuery` concat | `mysql.query` concat | `cursor.execute` f-string | `SqlCommand` concat |
| XSS | 79 | HTML concat response | `res.send` concat | HTML concat response | `Content(..., "text/html")` concat |
| Command Injection | 78 | `Runtime.exec` | `child_process.exec` | `os.system` | `Process.Start("cmd.exe","/c ...")` |
| Path Traversal | 22 | `Files.readAllBytes` | `fs.readFileSync` | `open(base+name)` | `File.ReadAllText` |
| RCE (code eval) | 94 | `ScriptEngine.eval` | `eval()` | `eval()` | CodeDom `CompileAssemblyFromSource` |
| XXE | 611 | `DocumentBuilderFactory` (DTD on) | `libxmljs noent:true` | lxml `resolve_entities=True` | `DtdProcessing.Parse` + resolver |
| Deserialization | 502 | `ObjectInputStream.readObject` | `node-serialize.unserialize` | `pickle.loads` | `BinaryFormatter.Deserialize` |
| SSTI | 1336 | Freemarker `new Template` | `ejs.render` | `render_template_string` | RazorEngine `RunCompile` |

### Category B — non-sink (Joern entrypoint → forward analysis)

| Type | CWE | Demonstration |
|------|-----|---------------|
| IDOR | 639 | `GET /users/{id}` with no ownership check |
| Business Logic Bypass | 840 | Negative transfer amounts; unlimited coupon reuse |
| Race Condition (TOCTOU) | 367 | Check-then-act on a balance with no lock |
| Privilege Escalation | 269 | Profile update persists a `role` field |
| Mass Assignment | 915 | Whole request body bound/merged onto the entity |
| Broken Access Control | 862 | Admin endpoints with no authorization at all |
| Authentication Flaws | 287 | Hardcoded weak JWT secret; predictable reset token |

### Difficulty mix (category A)

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
joern-parse targets/csharp-aspnet --output cs_cpg.bin

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

# 3a. Joern entrypoint enumeration (JSON lines; works for all 4 languages)
joern --script analysis/joern/find_entrypoints.sc py_cpg.bin

# 3b. Joern forward trace: entrypoint -> callee -> ... -> leaves, sinks marked
joern --script analysis/joern/forward_from_entrypoints.sc py_cpg.bin

# 4. Extract source snippets for every sink chain (JSON lines, LLM-ready)
SINKS_FILE=/tmp/sinks_py.json joern --script analysis/joern/extract_chain_snippets.sc py_cpg.bin > /tmp/snippets_py.jsonl

# 5. Dataflow confirmation: does request input actually reach each sink argument?
SINKS_FILE=/tmp/sinks_py.json joern --script analysis/joern/taint_confirm.sc py_cpg.bin > /tmp/taint_py.jsonl

# 6. LLM judgment (category A): is each sink->entrypoint chain a real vulnerability?
#    (DeepSeek via pydantic-ai; needs DEEPSEEK_API_KEY in env or .env)
uv run scripts/llm_judge_sink_chains.py --snippets /tmp/snippets_py.jsonl \
    --ground-truth targets/python-flask/ground_truth.json -o /tmp/verdicts_py.jsonl

# 7. Category B (non-sink): extract handler + forward-reachable source per entrypoint
SRC_ROOT=targets/python-flask joern --script analysis/joern/extract_entrypoint_snippets.sc py_cpg.bin > /tmp/ep_snippets_py.jsonl

# 8. LLM judgment (category B): judge each endpoint against all 7 non-sink classes
uv run scripts/llm_judge_entrypoints.py --snippets /tmp/ep_snippets_py.jsonl \
    --ground-truth targets/python-flask/ground_truth.json -o /tmp/verdicts_b_py.jsonl
```

Files:

| Path | Purpose |
| ---- | ------- |
| `analysis/rules/sinks-{python,java,js,csharp}.yml` | Semgrep sink rules, 8 category-A classes per language |
| `scripts/semgrep_to_sinks.py` | Semgrep JSON → compact sink list (`file`/`line`/`rule`/`vuln_type`) |
| `analysis/joern/find_entrypoints.sc` | Entrypoint enumeration (Flask routes, Spring mappings, Express router calls, ASP.NET attributes) |
| `analysis/joern/backward_from_sinks.sc` | Reverse call-chain walk from each sink to an entrypoint |
| `analysis/joern/forward_from_entrypoints.sc` | Forward call-graph walk from each entrypoint, sinks marked |
| `analysis/joern/extract_chain_snippets.sc` | Dumps source code of every method on each sink→entrypoint chain (JSON lines; set `SRC_ROOT` to the parse root when the frontend leaves method `code` empty) |
| `analysis/joern/extract_entrypoint_snippets.sc` | Dumps every HTTP entrypoint plus the source of its forward-reachable callees (BFS depth ≤ 5, JSON lines; `SRC_ROOT` as above) — input for the category-B LLM path |
| `analysis/joern/taint_confirm.sc` | Dataflow confirmation: `sink.argument.reachableByFlows(request.* sources)` per Semgrep sink; JSON lines with `CONFIRMED`/`UNCONFIRMED` + flow paths |
| `scripts/llm_judge_sink_chains.py` | LLM judgment layer, category A (pydantic-ai + DeepSeek): synthesizes each sink→entrypoint chain's snippets into a prompt, returns a structured verdict, and scores recall/FP against `ground_truth.json` (`--from-verdicts` re-scores without re-calling the LLM) |
| `scripts/llm_judge_entrypoints.py` | LLM judgment layer, category B (same DeepSeek setup): judges each entrypoint + forward-reachable source against all 7 non-sink classes and scores the category-B ground-truth entries (file+function match, route fallback) |

The same commands work for the other targets — swap the rules file
(`sinks-java.yml`, `sinks-js.yml`, `sinks-csharp.yml`) and the CPG.

## Notes

- Joern's C# frontend (csharpsrc2cpg) is less mature; expect coarser CPGs for
  `csharp-aspnet` (attribute routing / model binding only partially modeled).
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
    OSS dataflow across files — instance-field chains (java/python/csharp)
    are tracked, module-scope variables are not.
  - **csharp**: in-controller sinks CONFIRMED (controller action params as
    sources); cross-file flows into `Services/` are lost (frontend
    limitation), so `cs-cmdi-02`, `cs-path-traversal-01` stay UNCONFIRMED.
