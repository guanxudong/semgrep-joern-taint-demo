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
- Each target has `ground_truth.json` + `GROUND_TRUTH.md` (kept in sync).
- `analysis/rules/` — Semgrep sink rules per language (8 category-A classes).
- `analysis/joern/` — Joern scripts: entrypoint enumeration, sink→entrypoint
  backward trace, entrypoint→down forward trace, chain source-snippet
  extraction (`extract_chain_snippets.sc`; set `SRC_ROOT` to the parse root),
  dataflow taint confirmation (`taint_confirm.sc`).
- `scripts/semgrep_to_sinks.py` — converts Semgrep JSON into the sink list
  consumed by `backward_from_sinks.sc` (via `SINKS_FILE`).

## Vulnerability taxonomy

15 classes per project: 8 sink-based category A (sqli, xss, cmdi,
path-traversal, rce, xxe, deserialization, ssti) and 7 non-sink category B
(idor, business-logic, race-condition, priv-esc, mass-assignment,
broken-access-control, auth-flaws), plus 5 negative samples.

## Changing the targets

When adding/modifying a vulnerability:

1. Keep the `VULN: <id>` / `SAFE: <id>` comment directly above the handler.
2. Update **both** `ground_truth.json` and `GROUND_TRUTH.md` in that project —
   ids, routes, functions, sink, chain must match the code exactly.
3. Mirror the change across the other three projects if it is a taxonomic
   change (same `vuln_type` set everywhere).
4. Validate: `python3 -m json.tool <project>/ground_truth.json` and, for
   Python files, `python3 -m py_compile`.

## Testing changes

- Python: `python3 -m py_compile` all `.py` in the target.
- JS: `node --check` all `.js` in the target (TS is verified via joern-parse).
- All: `python3 -m json.tool` on each `ground_truth.json`.
- Parse check: `joern-parse targets/<name> --output /tmp/<name>.cpg.bin` must
  succeed; `semgrep targets/<name>` must run without parse errors.
