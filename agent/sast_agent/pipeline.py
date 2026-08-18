"""Deterministic screening pipeline for the SAST agent (M1).

Thin wrappers over the same stages as agent/run_baseline.py
(semgrep -> semgrep_to_sinks.py -> joern-parse -> backward_from_sinks.sc ->
taint_confirm.sc -> extract_chain_snippets.sc), with every stage's output
cached under workspace/agent-cache/<target>/ so repeat agent-tool calls are
cheap. All functions are synchronous; the investigator (M2) may run them in
a thread. Only facts are returned — no verdicts.

Usage:
    from sast_agent import pipeline
    sinks = pipeline.run_semgrep("python-flask")
    briefs = pipeline.screen("python-flask")
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from . import config
from .contracts import Chain, Gap, InvestigationBrief, Sink, TaintFlow

REPO = config.REPO


def _log(msg: str) -> None:
    print(f"[sast-pipeline {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def _run(cmd: list[str], env: dict | None = None, stdout_to: Path | None = None,
         timeout: int = 3600) -> str:
    """Run cmd from the repo root; raise on non-zero exit. Returns stdout."""
    _log("$ " + " ".join(cmd))
    full_env = {**os.environ, **(env or {})}
    if stdout_to:
        with open(stdout_to, "w") as out:
            proc = subprocess.run(cmd, cwd=REPO, env=full_env, stdout=out,
                                  stderr=subprocess.PIPE, text=True, timeout=timeout)
        stdout = ""
    else:
        proc = subprocess.run(cmd, cwd=REPO, env=full_env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=timeout)
        stdout = proc.stdout
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return stdout


_pre_done: set[str] = set()


def _prepare_tree(target: str) -> dict:
    """Target config, after running any pre step (jsp-legacy transpile).
    The pre step runs ONCE per process: it deletes+regenerates the tree
    (rmtree), so re-running it per pipeline call is both racy and
    invalidates CPG staleness checks mid-run."""
    cfg = config.target_cfg(target)
    if cfg.get("pre") and target not in _pre_done:
        _run(cfg["pre"])
        _pre_done.add(target)
    return cfg


def _sink_key(file: str, line: int, rule: str) -> str:
    return f"{file}:{line}:{rule}"


def _lookup(records: dict, sink: Sink):
    """Find a chains/taint record for a Sink. Joern snaps the Semgrep line
    hint to the nearest CPG call node (±3 window), so fall back to the
    nearest record with the same file+rule when the exact id misses."""
    if sink.id in records:
        return records[sink.id]
    best, best_dist = None, 4
    for key, value in records.items():
        f, line, rule = key.rsplit(":", 2)
        if f == sink.file and rule == sink.rule:
            dist = abs(int(line) - sink.line)
            if dist < best_dist:
                best, best_dist = value, dist
    return best


def _derive_name(matched_line: str, rule: str) -> str:
    """Sink function name from the semgrep-matched code line (last call in
    the line); fall back to the rule-derived name."""
    calls = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", matched_line)
    if calls:
        return calls[-1]
    m = re.search(r"sink-(.+)$", rule)
    return m.group(1) if m else rule


def run_semgrep(target: str, force: bool = False) -> list[Sink]:
    """semgrep --json -> semgrep_to_sinks.py -> list[Sink] (cached)."""
    cfg = _prepare_tree(target)
    cache = config.cache_dir(target)
    raw, sinks_json = cache / "semgrep_raw.json", cache / "sinks.json"

    if not sinks_json.exists() or force:
        _run(["semgrep", "--config", cfg["rules"], "--json", "--no-git-ignore",
              "-o", str(raw), cfg["tree"]])
        _run(["python3", "scripts/semgrep_to_sinks.py", str(raw),
              "--root", cfg["tree"], "-o", str(sinks_json)])

    # matched code lines, for sink-name derivation
    matched: dict[tuple[str, int, str], str] = {}
    if raw.exists():
        for r in json.loads(raw.read_text()).get("results", []):
            path = r.get("path", "")
            if path.startswith(cfg["tree"] + "/"):
                path = path[len(cfg["tree"]) + 1:]
            key = (path, r.get("start", {}).get("line", -1),
                   r.get("check_id", "").split(".")[-1])
            matched[key] = r.get("extra", {}).get("lines", "")

    sinks = []
    for s in json.loads(sinks_json.read_text()):
        line = matched.get((s["file"], s["line"], s["rule"]), "")
        sinks.append(Sink(
            id=_sink_key(s["file"], s["line"], s["rule"]),
            file=s["file"], line=s["line"], rule=s["rule"],
            vuln_type=s["vuln_type"],
            name=_derive_name(line, s["rule"]),
        ))
    return sinks


def ensure_cpg(target: str, force: bool = False) -> Path:
    """Build workspace/agent-cache/<target>/cpg.bin via joern-parse; rebuild
    only when missing or older than the newest source file in the tree."""
    cfg = _prepare_tree(target)
    cpg = config.cache_dir(target) / "cpg.bin"

    def stale() -> bool:
        if not cpg.is_file():
            return True
        cpg_mtime = cpg.stat().st_mtime
        newest = max((f.stat().st_mtime for f in cfg["tree_path"].rglob("*")
                      if f.is_file()), default=0.0)
        return cpg_mtime < newest

    if force or stale():
        _run([config.JOERN_PARSE, cfg["tree"], "--output", str(cpg)])
    else:
        _log(f"  skip (cached): {cpg}")
    return cpg


def get_chains(target: str, force: bool = False) -> dict[str, list[Chain]]:
    """backward_from_sinks.sc -> {sink_id: [Chain, ...]} (cached)."""
    cfg = _prepare_tree(target)
    sinks_json = config.cache_dir(target) / "sinks.json"
    if not sinks_json.exists() or force:
        run_semgrep(target, force=force)
    cpg = ensure_cpg(target, force=force)
    out = config.cache_dir(target) / "chains.jsonl"

    if not out.exists() or force:
        _run(["joern", "--script", "analysis/joern/backward_from_sinks.sc", str(cpg)],
             env={"SINKS_FILE": str(sinks_json), "CHAINS_JSON": str(out)})

    chains: dict[str, list[Chain]] = {}
    for line in out.read_text().splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        s = rec["sink"]
        chains[_sink_key(s["file"], s["line"], s["rule"])] = [
            Chain(**c) for c in rec["chains"]]
    return chains


def _flow_to_str(flow: dict) -> str:
    """Render one taint flow as a readable source->sink path string."""
    steps = " -> ".join(
        f"{p['file']}:{p['line']} `{p['code'].splitlines()[0].strip()[:80]}`"
        for p in flow.get("path", []))
    return f"{flow.get('source_method', '?')}: {steps}"


def get_taint_flows(target: str, force: bool = False) -> dict[str, TaintFlow]:
    """taint_confirm.sc -> {sink_id: TaintFlow} (cached)."""
    cfg = _prepare_tree(target)
    sinks_json = config.cache_dir(target) / "sinks.json"
    if not sinks_json.exists() or force:
        run_semgrep(target, force=force)
    cpg = ensure_cpg(target, force=force)
    out = config.cache_dir(target) / "taint.jsonl"

    if not out.exists() or force:
        _run(["joern", "--script", "analysis/joern/taint_confirm.sc", str(cpg)],
             env={"SINKS_FILE": str(sinks_json)}, stdout_to=out)

    flows: dict[str, TaintFlow] = {}
    for line in out.read_text().splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        s = rec["sink"]
        flows[_sink_key(s["file"], s["line"], s["rule"])] = TaintFlow(
            confirmed=rec.get("status") == "CONFIRMED",
            flows=[_flow_to_str(f) for f in rec.get("flows", [])],
        )
    return flows


def get_chain_snippets(target: str, sink_key: str | None = None,
                       force: bool = False) -> list[dict]:
    """extract_chain_snippets.sc -> per-sink snippet records (cached).
    Records: {"sink": {...}, "chains": [...], "snippets": [{function, file,
    start_line, end_line, code}, ...]}. Filtered to sink_key when given."""
    cfg = _prepare_tree(target)
    sinks_json = config.cache_dir(target) / "sinks.json"
    if not sinks_json.exists() or force:
        run_semgrep(target, force=force)
    cpg = ensure_cpg(target, force=force)
    out = config.cache_dir(target) / "snippets.jsonl"

    if not out.exists() or force:
        _run(["joern", "--script", "analysis/joern/extract_chain_snippets.sc", str(cpg)],
             env={"SINKS_FILE": str(sinks_json), "SRC_ROOT": cfg["tree"]},
             stdout_to=out)

    records = []
    for line in out.read_text().splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        rec = json.loads(line)
        s = rec.get("sink", {})
        if sink_key is not None and _sink_key(
                s.get("file", ""), s.get("line", -1), s.get("rule", "")) != sink_key:
            continue
        records.append(rec)
    return records


def screen(target: str, force: bool = False) -> list[InvestigationBrief]:
    """Orchestrate the deterministic screening and classify each sink's gap
    (§6A 信号层): no chains -> GAP_NO_CHAIN; chains but taint not confirmed
    -> GAP_FLOW_DEAD; otherwise OK."""
    sinks = run_semgrep(target, force=force)
    chains = get_chains(target, force=force)
    taints = get_taint_flows(target, force=force)

    raw_meta: dict[str, dict] = {}
    sinks_json = config.cache_dir(target) / "sinks.json"
    for s in json.loads(sinks_json.read_text()):
        raw_meta[_sink_key(s["file"], s["line"], s["rule"])] = {
            "cwe": s.get("cwe", "")}

    briefs = []
    for sink in sinks:
        sink_chains = _lookup(chains, sink)
        taint = _lookup(taints, sink)
        if not sink_chains:
            gap = Gap.GAP_NO_CHAIN
        elif taint is None or not taint.confirmed:
            gap = Gap.GAP_FLOW_DEAD
        else:
            gap = Gap.OK
        # TODO(M3): GAP_MISSING_STORE — chain/taint exist but a field/module
        # variable write site is missing from the chain. Needs chain/write-site
        # analysis; never emitted in M1.
        briefs.append(InvestigationBrief(
            sink=sink,
            semgrep=raw_meta.get(sink.id, {}),
            chains=sink_chains or None,
            taint=taint,
            gap=gap,
        ))
    return briefs
