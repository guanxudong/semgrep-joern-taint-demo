"""Agent tool set for the SAST agent (AGENT_MVP_PLAN.md §5 + §6A).

SastTools wraps one benchmark target; each method is a thin, fact-only
wrapper over the deterministic pipeline (pipeline.py), ripgrep, disk slices,
or parameterized Joern query templates. investigator.py (M2) registers these
with pydantic-ai. All writes are confined to the instance's cache dir;
targets/ is read-only and ground-truth files are refused everywhere (§9).

Usage:
    tools = SastTools("python-flask")
    tools.get_chains("data/db.py:16:py-sink-sqli")
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from . import config, pipeline
from .contracts import Finding, Sink

REPO = config.REPO

# Red line §9.2: never readable through any tool.
GROUND_TRUTH_NAMES = {"ground_truth.json", "GROUND_TRUTH.md"}

REPO_MAP_MAX_CHARS = 4000
SEARCH_MAX_LINES = 100
JOERN_QUERY_MAX_ROWS = 50

# §6A: parameterized joern_query templates only — no free Scala in M1.
JOERN_QUERY_TEMPLATES = ("callers_of", "writes_to", "reads_of", "methods_in_file")

_JOERN_QUERY_FALLBACK = (
    "ad-hoc queries failing repeatedly — fall back to "
    "read_function/search_code manual relay"
)

# Scala preamble: same import + minimal JSON escaping helpers as
# analysis/joern/*.sc. `arg` is injected as a quoted literal by the caller
# (quotes/newlines/backslashes rejected beforehand).
_PREAMBLE = r'''import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

def esc(s: String): String = s.flatMap {
  case '"'  => "\\\""
  case '\\' => "\\\\"
  case '\n' => "\\n"
  case '\r' => "\\r"
  case '\t' => "\\t"
  case c    => c.toString
}
def q(s: String): String = "\"" + esc(s) + "\""

val arg: String = %ARG%
'''

# Each template prints one JSON object per row; a trailing "// rows: N"
# comment line (ignored by the parser) makes empty results visible in logs.
_BODIES = {
    # callers_of(methodName) — all callers of X (exact name, falling back to
    # a contains-match so "query" also finds query_unsafe/query_safe).
    "callers_of": r'''
{
  var ms = cpg.method.nameExact(arg).l
  if (ms.isEmpty)
    ms = cpg.method.name(".*" + java.util.regex.Pattern.quote(arg) + ".*").l
  val rows = ms.flatMap(m => m.caller.l).distinct.map { c =>
    s"""{"caller":${q(c.fullName)},"file":${q(c.file.name.headOption.getOrElse("?"))},"line":${c.lineNumber.getOrElse(-1)}}"""
  }
  rows.take(50).foreach(println)
  println("// rows: " + rows.size)
}
''',
    # writes_to(varName) — all assignment points to a variable/field
    # (matches plain `x` and field writes like `self.x` / `this.x`).
    "writes_to": r'''
{
  val rows = cpg.assignment.l.filter { a =>
    val t = a.target.code
    t == arg || t.endsWith("." + arg)
  }.map { a =>
    s"""{"file":${q(a.file.name.headOption.getOrElse("?"))},"line":${a.lineNumber.getOrElse(-1)},"code":${q(a.code.take(200))},"method":${q(a.method.fullName)}}"""
  }
  rows.take(50).foreach(println)
  println("// rows: " + rows.size)
}
''',
    # reads_of(varName) — all read points (identifier occurrences that are
    # not the target of an assignment).
    "reads_of": r'''
{
  val rows = cpg.identifier.nameExact(arg).l.filter { i =>
    i.astParent match {
      case c: nodes.Call =>
        !(c.name == "<operator>.assignment" &&
          c.argument(1).code == arg)
      case _ => true
    }
  }.map { i =>
    s"""{"file":${q(i.file.name.headOption.getOrElse("?"))},"line":${i.lineNumber.getOrElse(-1)},"code":${q(i.code.take(200))},"method":${q(i.method.fullName)}}"""
  }
  rows.take(50).foreach(println)
  println("// rows: " + rows.size)
}
''',
    # methods_in_file(file) — helper: all methods in a file (basename or
    # tree-relative suffix).
    "methods_in_file": r'''
{
  val rows = cpg.method.l.filter { m =>
    m.file.name.headOption.exists(f => f == arg || f.endsWith("/" + arg))
  }.map { m =>
    s"""{"name":${q(m.name)},"fullName":${q(m.fullName)},"file":${q(m.file.name.headOption.getOrElse("?"))},"line":${m.lineNumber.getOrElse(-1)}}"""
  }
  rows.take(50).foreach(println)
  println("// rows: " + rows.size)
}
''',
}


def _parse_json_lines(stdout: str, max_rows: int) -> list:
    """Collect JSON objects/arrays from joern stdout (skips [INFO] logs)."""
    rows = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{") or line.startswith("["):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(rows) >= max_rows:
                break
    return rows


class SastTools:
    """The agent's tool set for one benchmark target."""

    def __init__(self, target: str, cache_dir: Path | None = None):
        self.target = target
        self.cfg = config.target_cfg(target)
        self.tree = self.cfg["tree_path"]
        self.cache_dir = Path(cache_dir) if cache_dir else config.cache_dir(target)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._joern_failures = 0

    # ---- pipeline-backed tools (facts from the deterministic screening) ----

    def get_repo_map(self, force: bool = False) -> str:
        """tree-sitter repo map JSON (truncated to ~4000 chars)."""
        md = self.cache_dir / "REPO_MAP.md"
        js = self.cache_dir / "repo_map.json"
        if not js.exists() or force:
            pipeline._run(["uv", "run", "scripts/repo_map.py", self.cfg["tree"],
                           "-o", str(md), "--json", str(js)])
        text = js.read_text()
        if len(text) > REPO_MAP_MAX_CHARS:
            text = text[:REPO_MAP_MAX_CHARS] + "\n... [truncated]"
        return text

    def run_semgrep(self, force: bool = False) -> list[dict]:
        """Semgrep sink list as dicts (Sink.model_dump())."""
        return [s.model_dump() for s in pipeline.run_semgrep(self.target, force=force)]

    def _find_sink(self, sink_id: str) -> Sink:
        for s in pipeline.run_semgrep(self.target):
            if s.id == sink_id:
                return s
        raise ValueError(f"unknown sink_id: {sink_id} "
                         f"(run_semgrep first to list valid ids)")

    def get_chains(self, sink_id: str, force: bool = False) -> list[dict]:
        """Entrypoint->sink call chains for one sink (possibly empty)."""
        sink = self._find_sink(sink_id)
        chains = pipeline._lookup(pipeline.get_chains(self.target, force=force), sink)
        return [c.model_dump() for c in (chains or [])]

    def get_taint_flows(self, sink_id: str, force: bool = False) -> dict:
        """Dataflow taint confirmation for one sink."""
        sink = self._find_sink(sink_id)
        flow = pipeline._lookup(pipeline.get_taint_flows(self.target, force=force), sink)
        return flow.model_dump() if flow else {"confirmed": False, "flows": []}

    def get_chain_snippets(self, sink_id: str, force: bool = False) -> list[dict]:
        """Source snippets of every method on the sink's chains."""
        return pipeline.get_chain_snippets(self.target, sink_key=sink_id, force=force)

    # ---- drill-down tools (dynamic investigation) ----

    def read_function(self, file: str, start: int, end: int) -> str:
        """Disk slice of <tree>/<file> lines start..end (1-based, inclusive).
        Refuses paths escaping the target tree and ground-truth files."""
        if os.path.basename(file) in GROUND_TRUTH_NAMES:
            return "ERROR: access to ground truth files is refused (red line)"
        root = self.tree.resolve()
        path = (root / file).resolve()
        if path != root and root not in path.parents:
            return f"ERROR: path escapes the target tree: {file}"
        if not path.is_file():
            return f"ERROR: not a file: {file}"
        lines = path.read_text(errors="replace").splitlines()
        start = max(1, start)
        end = min(end, len(lines))
        if start > end:
            return f"ERROR: no lines in range {start}..{end} ({file} has {len(lines)})"
        return "\n".join(f"{i:>4}: {lines[i - 1]}" for i in range(start, end + 1))

    def search_code(self, pattern: str, glob: str | None = None) -> str:
        """ripgrep under the target tree (±2 lines of context, ~100 lines
        max). Ground-truth files are always excluded."""
        cmd = ["rg", "--line-number", "--context", "2",
               "--glob", "!**/ground_truth.json",
               "--glob", "!**/GROUND_TRUTH.md"]
        if glob:
            cmd += ["--glob", glob]
        cmd += ["--", pattern, str(self.tree)]
        proc = subprocess.run(cmd, cwd=REPO, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
        if proc.returncode not in (0, 1):  # 1 = no matches
            return f"ERROR: rg failed ({proc.returncode}): {proc.stderr.strip()[:400]}"
        lines = proc.stdout.splitlines()
        if len(lines) > SEARCH_MAX_LINES:
            lines = lines[:SEARCH_MAX_LINES] + ["... [truncated]"]
        return "\n".join(lines) if lines else "(no matches)"

    def joern_query(self, template: str, arg: str) -> list | str:
        """Parameterized CPG query (§6A): one of JOERN_QUERY_TEMPLATES.
        Returns parsed JSON rows (max 50). After MAX_JOERN_QUERY_RETRIES
        consecutive failures, stops running and returns a fallback hint."""
        if self._joern_failures >= config.MAX_JOERN_QUERY_RETRIES:
            return _JOERN_QUERY_FALLBACK
        if template not in _BODIES:
            return (f"ERROR: unknown template {template!r} "
                    f"(allowed: {JOERN_QUERY_TEMPLATES})")
        if any(ch in arg for ch in ('"', "\n", "\r", "\\")):
            return "ERROR: arg must not contain quotes, backslashes or newlines"

        script = self.cache_dir / f"joern_query_{template}.sc"
        script.write_text(_PREAMBLE.replace("%ARG%", json.dumps(arg))
                          + _BODIES[template])
        try:
            cpg = pipeline.ensure_cpg(self.target)
            proc = subprocess.run(
                ["joern", "--script", str(script), str(cpg)],
                cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=300)
        except Exception as e:
            self._joern_failures += 1
            return f"ERROR: joern_query failed: {e}"
        if proc.returncode != 0:
            self._joern_failures += 1
            tail = "\n".join(
                ln for ln in (proc.stderr + proc.stdout).splitlines()
                if "error" in ln.lower())[-800:]
            return f"ERROR: joern_query failed ({proc.returncode}): {tail}"
        self._joern_failures = 0
        return _parse_json_lines(proc.stdout, JOERN_QUERY_MAX_ROWS)

    def list_entrypoints(self, force: bool = False) -> list[dict]:
        """HTTP entrypoint enumeration (find_entrypoints.sc, cached)."""
        out = self.cache_dir / "entrypoints.jsonl"
        if not out.exists() or force:
            cpg = pipeline.ensure_cpg(self.target)
            stdout = pipeline._run(
                ["joern", "--script", "analysis/joern/find_entrypoints.sc", str(cpg)])
            out.write_text(stdout)
        return _parse_json_lines(out.read_text(), 500)

    # ---- finding submission ----

    def submit_finding(self, finding: dict) -> dict:
        """Validate and record a Finding; ends the current sink's
        investigation. (Budget enforcement is M2's job.)"""
        try:
            f = Finding.model_validate(finding)
        except Exception as e:
            return {"ok": False, "error": f"invalid Finding: {e}"}
        out = self.cache_dir / "findings.jsonl"
        with open(out, "a") as fh:
            fh.write(f.model_dump_json() + "\n")
        return {"ok": True, "sink": f.sink.id, "written_to": str(out)}
