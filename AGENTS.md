# Agent Guidance: Bad Demo

This repository is an **intentionally vulnerable** Python/Flask application used
to demonstrate SAST, cross-file taint analysis, and OWASP Top 10 coverage with
Semgrep and Joern.

## Core constraints

- **Do not fix the vulnerabilities.** Every weakness is deliberate and serves
  the demo. Patches should only be added if the user explicitly asks for a
  "fixed" comparison branch or exercise.
- **Do not add production-grade hardening.** Avoid adding authentication,
  authorization, parameterized queries, or other fixes that would break the
  intentionally vulnerable examples.
- **Keep dependencies intentionally outdated.** `pyproject.toml` pins older
  versions (e.g. Flask 2.0.0, Werkzeug <2.1, requests 2.25.0) to demonstrate
  A06:2021. Do not upgrade them unless the user specifically requests it.
- **Do not commit generated artifacts.** CPGs (`bad_demo_cpg.bin`, `workspace/`,
  `*.cpg.bin`), Semgrep outputs (`semgrep_results.json`, `semgrep_df.json`,
  `semgrep_scan.log`), and generated reports (`joern_walkthrough.html`) are all
  gitignored and must be regenerated locally.

## Project layout

- `src/bad_demo/` - Vulnerable application code. Each file maps to one or more
  OWASP Top 10 2021 categories.
- `joern/` - Scala/Joern query scripts for graph-based taint analysis.
- `scripts/` - Python helpers for processing Semgrep JSON output.
- `pyproject.toml` - uv-based Python project configuration.

## Build and run

Use `uv` for all Python operations:

```bash
uv sync              # install dependencies
uv run bad-demo      # run the Flask app
uvx bandit -r src/bad_demo   # optional Bandit scan
```

## Working with Joern scripts

All scripts in `joern/` assume the current working directory is the repository
root because they use relative paths such as `bad_demo_cpg.bin` and
`src/bad_demo/...`.

Generate the CPG first:

```bash
joern-parse src/bad_demo --output bad_demo_cpg.bin
```

Then run individual scripts:

```bash
joern --script joern/cpg_overview.sc
joern --script joern/find_sinks.sc
```

When editing Joern scripts:
- Keep imports explicit: `io.shiftleft.semanticcpg.language._` and
  `io.joern.dataflowengineoss.language._` where taint is needed.
- Prefer `.l` or `.nonEmpty` to force evaluation before printing.
- Preserve the tutorial style: print clear section headers and concise output.

## Working with Python helpers

`scripts/map_semgrep_to_functions.py` is a standalone CLI tool. It expects a
Semgrep JSON file:

```bash
python scripts/map_semgrep_to_functions.py semgrep_results.json
```

Keep it compatible with Python 3.10+ and avoid adding third-party dependencies.

## README maintenance

When adding new vulnerability examples or analysis scripts:
1. Update the OWASP Top 10 mapping table in `README.md`.
2. Add cross-file taint examples if the new code spans multiple files.
3. List new Joern scripts in the script reference table.
4. Keep the tutorial flow: Semgrep scan → CPG generation → Joern scripts →
   Python bridge.

## Testing changes

Before declaring work complete:
- Run `uv run python -m py_compile src/bad_demo/*.py scripts/*.py` to confirm
  Python files are syntactically valid.
- Run `uv run bad-demo` briefly to confirm the Flask app starts.
- Run `semgrep --config=auto src/bad_demo` to confirm findings still appear.
- If you changed a Joern script, regenerate the CPG and run the script to
  confirm it still executes without errors.
