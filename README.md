# Bad Demo: Taint Analysis Tutorial

An intentionally vulnerable Python project for demonstrating **cross-file taint
analysis** with **Semgrep** and **Joern**. Every weakness is mapped to an
OWASP Top 10 2021 category so the demo can double as a SAST tool comparison.

> ⚠️ **DO NOT deploy or use this code in production.** All vulnerabilities are
deliberate and unpatched for educational purposes.

## What you will see

- **Semgrep** quickly finds risky call sites (sinks) using lightweight rules.
- **Joern** builds a Code Property Graph (CPG) and traces taint from HTTP
  sources (e.g. `request.args.get`) across multiple files to the final sinks
  (e.g. `cursor.execute`, `os.system`, `requests.get`).
- A small Python bridge maps Semgrep findings to their enclosing functions so
  you can use the results alongside the CPG-based function mapping.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) for Python dependencies
- [Semgrep](https://semgrep.dev/) for rule-based scanning
- [Joern](https://joern.io/) for graph-based taint analysis

The `.python-version` file pins the interpreter to **CPython 3.11**, which is
compatible with the intentionally older Flask/Werkzeug versions used for the
A06:2021 demonstration.

## Project layout

```text
src/bad_demo/
├── app.py              # Flask routes that wire sources to sinks
├── auth.py             # Broken authentication / JWT (A07)
├── config.py           # Hardcoded secrets, debug mode (A05)
├── crypto.py           # Weak hashing and crypto (A02)
├── db.py               # SQL injection sinks (A03)
├── deserialization.py  # Pickle / YAML unsafe load (A08)
├── exec_utils.py       # OS command injection (A03)
├── http_utils.py       # SSRF (A10)
├── ldap_utils.py       # LDAP injection (A03)
├── logging_utils.py    # Sensitive data in logs (A09)
├── templates.py        # Reflected / stored XSS (A03)
└── templates/          # Jinja2 templates with | safe filters

joern/                  # Joern query scripts (run from repo root)
scripts/                # Python helpers that work with Semgrep JSON output
```

## OWASP Top 10 mapping

| File(s)                              | Category                                            |
| ------------------------------------ | --------------------------------------------------- |
| `app.py` (admin routes)              | A01:2021 - Broken Access Control                    |
| `crypto.py`, `auth.py`               | A02:2021 - Cryptographic Failures                   |
| `db.py`, `exec_utils.py`, ...        | A03:2021 - Injection (SQL, XSS, Command, LDAP)      |
| `app.py` (register)                  | A04:2021 - Insecure Design                          |
| `config.py`, `app.py` (debug_info)   | A05:2021 - Security Misconfiguration                |
| `pyproject.toml` (old deps)          | A06:2021 - Vulnerable and Outdated Components       |
| `auth.py`                            | A07:2021 - Identification and Authentication Failures |
| `deserialization.py`                 | A08:2021 - Software and Data Integrity Failures     |
| `logging_utils.py`                   | A09:2021 - Security Logging and Monitoring Failures |
| `http_utils.py`                      | A10:2021 - Server-Side Request Forgery              |

## Cross-file taint examples

1. **SQL injection**  
   `app.py:search()` → `request.args.get("q")` → `db.py:search_users_unsafe()` → `cursor.execute(...)`

2. **XSS**  
   `app.py:search()` → `q` → `templates.py:render_search_results()` → HTML string concatenation

3. **OS command injection**  
   `app.py:ping()` → `host` → `exec_utils.py:run_ping()` → `os.system(...)`

4. **SSRF**  
   `app.py:fetch()` → `url` → `http_utils.py:fetch_url()` → `requests.get(...)`

5. **Broken access control + SQL injection**  
   `app.py:admin_delete()` → token verification bypass → `db.py:delete_user_unsafe()`

## Running the application

```bash
uv sync
uv run bad-demo
```

The application listens on `http://0.0.0.0:5000`.

## Part 1 - SAST scanning with Semgrep

Run Semgrep against the source tree. The `--config=auto` flag uses Semgrep's
built-in ruleset and produces findings in JSON:

```bash
semgrep --config=auto --json --output=semgrep_results.json src/bad_demo
```

You can also try a quick text summary:

```bash
semgrep --config=auto src/bad_demo
```

Expected output: ~20+ findings covering SQLi, command injection, hardcoded
secrets, weak crypto, unsafe deserialization, SSRF, and more.

## Part 2 - Graph-based taint analysis with Joern

All Joern scripts live in `joern/` and assume you run them from the repository
root so that relative paths such as `bad_demo_cpg.bin` and `src/bad_demo/...`
resolve correctly.

### 1. Build the CPG

```bash
joern-parse src/bad_demo --output bad_demo_cpg.bin
```

This creates `bad_demo_cpg.bin` in the project root (it is gitignored).

### 2. Run the tutorial scripts

The scripts are designed to be run in order. Each one prints its results
straight to the terminal.

```bash
# 1. Inspect the graph: node/edge counts, files, methods, dangerous calls
joern --script joern/cpg_overview.sc

# 2. Enumerate sinks by category (SQLi, command injection, deserialization, ...)
joern --script joern/find_sinks.sc

# 3. For each SQL execute sink, check which parameters reach it and who calls it
joern --script joern/investigate_sinks.sc

# 4. Trace taint from source to sink for SQLi and command injection
joern --script joern/trace_taint.sc

# 5. Detailed sink-to-source walkthrough with code snippets
joern --script joern/sink_walkthrough.sc

# 6. Map Semgrep findings to their enclosing CPG functions
semgrep --config=auto --json --output=semgrep_results.json src/bad_demo
joern --script joern/joern_map_semgrep.sc
```

### Script reference

| Script | Purpose |
| ------ | ------- |
| `joern/cpg_overview.sc` | Graph stats, source files, method names, first dangerous calls |
| `joern/find_sinks.sc` | Enumerate sinks grouped by vulnerability class |
| `joern/investigate_sinks.sc` | Parameter reachability + caller analysis for SQL sinks |
| `joern/trace_taint.sc` | Step-by-step taint from HTTP source to SQL / command sinks |
| `joern/sink_walkthrough.sc` | Full sink-to-source walkthrough with printed code snippets |
| `joern/joern_map_semgrep.sc` | Bridge Semgrep JSON results into CPG function IDs |

## Part 3 - Bridging Semgrep and Joern with Python

Semgrep reports sinks as file/line pairs. For function-level prioritization you
often want the enclosing function. The helper script uses Python's `ast` module
to map each Semgrep result to its enclosing function:

```bash
semgrep --config=auto --json --output=semgrep_results.json src/bad_demo
python scripts/map_semgrep_to_functions.py semgrep_results.json
```

You can also produce the same function mapping from the CPG by running
`joern/joern_map_semgrep.sc` after generating the Semgrep results.

## License

This is educational demo code and is provided as-is without warranty.
