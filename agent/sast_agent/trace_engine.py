"""Directive execution layer for the tracer (A-class v2) — no LLM here.

Translates a TraceDirective from the closed menu into an engine call and
returns structured rows:

- joern-backed kinds (callers_of / writes_to / reads_of / find_call_sites /
  trace_back / methods_in_file) run analysis/joern/trace_step.sc against the
  cached CPG — one JVM launch per directive, one JSON row per candidate;
- read_file / search_code delegate to SastTools (red lines + scrub.py
  ground-truth stripping are inherited, not reimplemented);
- slice_source() serves the envelope builder (frontier/candidate snippets),
  always scrubbed.

Consecutive joern failures trip the same fallback as tools.joern_query:
after MAX_JOERN_QUERY_RETRIES the engine stops launching and tells the
tracer to degrade honestly instead of burning the wall clock.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from . import config, pipeline
from .contracts import Sink
from .scrub import scrub
from .tools import SastTools
from .trace_schema import Candidate, TraceDirective

REPO = config.REPO
TRACE_STEP_SCRIPT = REPO / "analysis" / "joern" / "trace_step.sc"

JOERN_KINDS = ("callers_of", "writes_to", "reads_of", "find_call_sites",
               "trace_back", "methods_in_file")
MAX_ROWS = 50

_FALLBACK = ("engine unavailable after repeated failures — finish with the "
             "context already gathered and lower confidence")


def _log(msg: str) -> None:
    print(f"[trace-engine {time.strftime('%H:%M:%S')}] {msg}",
          file=sys.stderr, flush=True)


class TraceEngine:
    """Executes trace directives for one target."""

    def __init__(self, target: str, cache_dir: Path | None = None):
        self.target = target
        self.cfg = config.target_cfg(target)
        self.tree = self.cfg["tree_path"]
        self.cache_dir = Path(cache_dir) if cache_dir else config.cache_dir(target)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # SastTools is reused for disk reads / ripgrep (scrub + red lines)
        # and for the screening-fact accessors the envelope builder needs.
        self.tools = SastTools(target, self.cache_dir)
        self._joern_failures = 0
        self.executions: list[dict] = []  # per-sink tool_log material

    # ---- public API ----

    def execute(self, directive: TraceDirective, sink: Sink | None = None):
        """Run one directive. Returns (rows, error):
        - rows: list[dict] of engine rows (Candidate-shaped minus id)
          for joern kinds; for read_file/search_code a single
          {"code": ...} row carrying the scrubbed text;
        - error: None or a human-readable failure string (the tracer feeds
          it back to the LLM next round instead of crashing).
        """
        kind = directive.kind
        try:
            if kind == "read_file":
                return self._read_file(directive), None
            if kind == "search_code":
                return self._search_code(directive), None
            if kind in JOERN_KINDS:
                return self._joern(directive)
            return [], f"unknown directive kind {kind!r}"
        except Exception as e:  # never let an engine hiccup kill the trace
            _log(f"directive failed: {kind} {directive.symbol}: {e}")
            return [], f"{type(e).__name__}: {e}"

    def slice_source(self, file: str, start: int, end: int,
                     max_lines: int = 120) -> str:
        """Scrubbed, numbered disk slice for the envelope builder.
        Recorded in executions: the report.py tool_log backing rule needs
        every file the LLM could have cited to appear in the log."""
        begin, stop = max(1, start), min(end, start + max_lines - 1)
        text = self.tools.read_function(file, begin, stop)
        self._record("read_slice", {"file": file, "start": begin, "end": stop},
                     text)
        return text

    # ---- disk-backed kinds (delegate to SastTools: red lines + scrub) ----

    def _read_file(self, d: TraceDirective) -> list[dict]:
        if not d.file:
            return [{"error": "read_file requires file"}]
        start = max(1, (d.line or 1) - 30)
        text = self.tools.read_function(d.file, start, start + 90)
        self._record("read_file", {"file": d.file, "line": d.line}, text)
        return [{"code": text}]

    def _search_code(self, d: TraceDirective) -> list[dict]:
        if not d.symbol:
            return [{"error": "search_code requires symbol (ripgrep pattern)"}]
        text = self.tools.search_code(d.symbol, d.file)
        self._record("search_code", {"pattern": d.symbol}, text)
        return [{"code": text}]

    # ---- joern-backed kinds ----

    def _joern(self, d: TraceDirective):
        if self._joern_failures >= config.MAX_JOERN_QUERY_RETRIES:
            return [], _FALLBACK
        directive_path = self.cache_dir / "trace_directive.json"
        directive_path.write_text(json.dumps({
            "kind": d.kind, "symbol": d.symbol,
            "file": d.file or "", "line": d.line or 0,
        }))
        cpg = pipeline.ensure_cpg(self.target)
        env = {"DIRECTIVE_FILE": str(directive_path),
               "SRC_ROOT": self.cfg["tree"]}
        _log(f"joern trace_step {d.kind}({d.symbol or d.file})")
        proc = subprocess.run(
            ["joern", "--script", str(TRACE_STEP_SCRIPT), str(cpg)],
            cwd=REPO, env={**os.environ, **env},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=300)
        if proc.returncode != 0:
            self._joern_failures += 1
            tail = "\n".join(
                ln for ln in (proc.stderr + proc.stdout).splitlines()
                if "error" in ln.lower())[-600:]
            return [], f"trace_step.sc failed ({proc.returncode}): {tail}"
        self._joern_failures = 0
        rows = self._parse(proc.stdout)
        self._record(f"joern:{d.kind}", {"symbol": d.symbol, "file": d.file},
                     json.dumps(rows))
        return rows, None

    @staticmethod
    def _parse(stdout: str) -> list[dict]:
        rows = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(rows) >= MAX_ROWS:
                    break
        return rows

    def _record(self, tool: str, args: dict, result: str) -> None:
        """Feed the report.py tool_log contract: every drilled file ref must
        be backed by a recorded engine/disk call."""
        import re
        refs = sorted({f"{f}:{n}" for f, n in re.findall(
            r"([\w./-]+\.(?:py|js|ts|java|cs|jsp)):(\d+)", result)})[:30]
        self.executions.append({
            "tool": tool,
            "args": {k: str(v)[:120] for k, v in args.items() if v is not None},
            "refs": refs,
        })


def rows_to_candidates(rows: list[dict], kind: str) -> list[Candidate]:
    """Shape engine rows as Candidates (ids assigned by the tracer)."""
    out = []
    for r in rows:
        out.append(Candidate(
            kind=kind,
            method=r.get("method", ""),
            file=r.get("file", ""),
            line=r.get("line", 0) or 0,
            line_end=r.get("line_end", 0) or 0,
            code=r.get("code", ""),
            note=r.get("route", "") or r.get("receiver", ""),
        ))
    return out
