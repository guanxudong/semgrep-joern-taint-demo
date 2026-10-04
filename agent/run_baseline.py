#!/usr/bin/env python3
"""M0 baseline runner: execute the deterministic Semgrep + Joern + LLM-judge
pipeline for every benchmark target and freeze the results as the regression
baseline (workspace/baseline/).

Per target <name>, artifacts land in workspace/baseline/<name>/:

  semgrep_raw.json     semgrep --json output
  sinks.json           compact sink list (semgrep_to_sinks.py)
  cpg.bin              Joern CPG
  chains.jsonl         backward_from_sinks.sc (CHAINS_JSON)
  taint.jsonl          taint_confirm.sc stdout
  chain_report.jsonl   per-chain CONFIRMED/UNCONFIRMED/NO_CHAIN (chain_report.py)
  snippets.jsonl       extract_chain_snippets.sc stdout (category A judge input)
  verdicts_a.jsonl     llm_judge_sink_chains.py verdicts
  judge_a_summary.txt  its stdout summary
  ep_snippets.jsonl    extract_entrypoint_snippets.sc stdout (category B input)
  verdicts_b.jsonl     llm_judge_entrypoints.py verdicts
  judge_b_summary.txt  its stdout summary

Aggregate metrics go to workspace/baseline/baseline.json.

Usage:
    python3 agent/run_baseline.py                      # all targets
    python3 agent/run_baseline.py --targets python-flask,java-spring
    python3 agent/run_baseline.py --skip-llm           # deterministic stages only
    python3 agent/run_baseline.py --force              # redo cached artifacts
    python3 agent/run_baseline.py --compare [summary.json]  # M5/M8 regression gate

M5/M8 regression gate (--compare, plan §8-M5/§8-M8): compares an agent batch
run's summary.json (A-class, run_agent) or summary_b.json (B-class,
run_worker) — auto-detected by content — (default: the latest
workspace/agent-reports/*/summary*.json) against this frozen baseline. Exit
code is non-zero when any compared target's recall drops below the baseline
(judge_a for A summaries, judge_b for B summaries) or a NEW safe-sample
false positive appears (FP ids already present in the baseline are
tolerated).

Gate semantics:
  PASS  target compared, no regression
  SKIP  target has no comparable baseline (e.g. frozen with --skip-llm, so
        judge_a/judge_b is empty) or the dimension's data is missing —
        never counted as a regression; --require-baseline turns SKIP into FAIL
  FAIL  regression (recall drop / new safe FP / over budget / leak)

Every failure is classified (provenance, BASELINE_VERSION 2) so a red gate
says WHICH of these moved: MODEL_DRIFT / CODE_CHANGED / SNIPPET_CHANGED /
ENGINE_CHANGED / JUDGE_CHANGED / CHAINS_CHANGED, else REAL_REGRESSION.
Extra gated dimensions:
  --max-token-delta PCT    tokens vs the previous same-shape batch summary
                           (the judge baseline's token count is not
                           comparable — different pipeline)
  --min-confirmed-rate PCT CONFIRMED/total chains of the run under test
  --forbid-leak            any certain ground-truth leak recorded in
                           workspace/leak-audit.jsonl after the summary

Every step is skipped when its output already exists (unless --force), so
re-runs are cheap and a crash can be resumed.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE_DIR = REPO / "workspace" / "baseline"
AGENT_CACHE = REPO / "workspace" / "agent-cache"
REPORT_ROOT = REPO / "workspace" / "agent-reports"
LEAK_AUDIT = REPO / "workspace" / "leak-audit.jsonl"
BASELINE_VERSION = 2
BASELINE_FILE = BASELINE_DIR / "baseline.json"

# Ground-truth records are not source code: a ground-truth edit must not
# read as a code change in the gate's classification.
GT_NAMES = {"ground_truth.json", "GROUND_TRUTH.md"}

# (provenance key, baseline artifact name, agent-cache artifact name) — the
# agent reuses the same joern scripts, so these are comparable across the
# two dirs (canonical-record hashing, see _records_sha).
_ARTIFACTS = (
    ("chains", "chains.jsonl", "chains.jsonl"),
    ("snippets", "snippets.jsonl", "snippets.jsonl"),
    ("ep_snippets", "ep_snippets.jsonl", "entrypoint_snippets.jsonl"),
)

# Files whose content defines the deterministic stage + the scrubber; a
# change here moves results without any target edit (ENGINE_CHANGED).
def _engine_files() -> list[Path]:
    return sorted((REPO / "analysis" / "joern").glob("*.sc")) + \
        sorted((REPO / "analysis" / "rules").glob("*.yml")) + \
        [REPO / "scripts" / "chain_report.py",
         REPO / "scripts" / "semgrep_to_sinks.py",
         REPO / "agent" / "sast_agent" / "scrub.py"]


def find_joern_parse() -> str:
    """joern-parse is not always on PATH; fall back to the joern-cli bundle."""
    import shutil
    return (os.environ.get("JOERN_PARSE")
            or shutil.which("joern-parse")
            or str(Path.home() / ".local" / "bin" / "joern-cli" / "joern-parse"))


JOERN_PARSE = find_joern_parse()

TARGETS = {
    "python-flask": {
        "rules": "analysis/rules/sinks-python.yml",
        "tree": "targets/python-flask",
        "ground_truth": "targets/python-flask/ground_truth.json",
    },
    "python-flask-enterprise": {
        "rules": "analysis/rules/sinks-python.yml",
        "tree": "targets/python-flask-enterprise",
        "ground_truth": "targets/python-flask-enterprise/ground_truth.json",
    },
    "java-spring": {
        "rules": "analysis/rules/sinks-java.yml",
        "tree": "targets/java-spring",
        "ground_truth": "targets/java-spring/ground_truth.json",
    },
    "js-ts-express": {
        "rules": "analysis/rules/sinks-js.yml",
        "tree": "targets/js-ts-express",
        "ground_truth": "targets/js-ts-express/ground_truth.json",
    },
    "csharp-aspnet": {
        "rules": "analysis/rules/sinks-csharp.yml",
        "tree": "targets/csharp-aspnet",
        "ground_truth": "targets/csharp-aspnet/ground_truth.json",
    },
}


def log(msg: str) -> None:
    print(f"[baseline {time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---- provenance (BASELINE_VERSION 2) -------------------------------------
# A recall drop is only actionable if you know what moved. These hashes let
# --compare say MODEL_DRIFT / CODE_CHANGED / SNIPPET_CHANGED / ENGINE_CHANGED
# instead of leaving the reader to guess (LIMITATIONS §4: model drift has
# silently flipped verdicts and forced two baseline re-pins).

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _records_sha(p: Path) -> str | None:
    """sha over the JSON RECORDS of a JSONL artifact, not its raw bytes.

    joern writes log lines to the same stdout as the payload, so raw hashes
    differ between runs of the same script (verified). Canonicalising the
    records makes baseline-dir and agent-cache hashes comparable — they are
    byte-different but record-identical for the same input.
    """
    if not p.exists():
        return None
    h = hashlib.sha256()
    n = 0
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        h.update(json.dumps(rec, sort_keys=True, ensure_ascii=False).encode())
        n += 1
    return f"{h.hexdigest()[:16]}:{n}" if n else None


def tree_sha(tree: Path) -> str:
    """sha over a target's source files (ground-truth records excluded)."""
    h = hashlib.sha256()
    n = 0
    for p in sorted(Path(tree).rglob("*")):
        if not p.is_file() or p.name in GT_NAMES or "__pycache__" in p.parts:
            continue
        h.update(str(p.relative_to(tree)).encode())
        h.update(p.read_bytes())
        n += 1
    return f"{h.hexdigest()[:16]}:{n}"


def _tool_version(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = (p.stdout or p.stderr).strip().splitlines()
        return out[0][:80] if out else "unknown"
    except Exception:
        return "unavailable"


def _joern_fingerprint() -> str:
    """Identify the joern install without shelling out.

    `joern --version` is not a supported flag (it tries to load a CPG from
    cwd), and the distribution carries no VERSION file — but it does ship
    `lib/io.joern.joern-cli-<version>.jar`, which names the version exactly.
    Falls back to hashing the lib listing (name + size + mtime), then to the
    launcher itself. Stable across runs, changes when the install does."""
    import shutil
    import hashlib as _h
    exe = shutil.which("joern") or ""
    if not exe:
        return "unavailable"
    home = Path(exe).resolve().parent
    # the distribution ships io.joern.joern-cli-<version>.jar, which names the
    # version exactly; fall back to hashing the lib listing
    named = sorted(home.glob("lib/io.joern.joern-cli-*.jar"))
    if named:
        return named[-1].stem.replace("io.joern.joern-cli-", "joern ")
    jars = sorted((home / "lib").glob("*.jar")) or sorted(home.glob("*.jar"))
    if not jars:
        return f"launcher:{_h.sha256(Path(exe).read_bytes()).hexdigest()[:12]}"
    h = _h.sha256()
    for p in jars:
        st = p.stat()
        h.update(f"{p.name}:{st.st_size}:{int(st.st_mtime)}".encode())
    return f"jars:{h.hexdigest()[:12]}"


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(REPO), *args],
                              capture_output=True, text=True,
                              timeout=30).stdout.strip()
    except Exception:
        return ""


def _model_env() -> dict:
    """LLM identity (never the key). Defaults mirror sast_agent/config.py."""
    return {
        "model": os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
        "base_url": os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
    }


def _target_state(name: str, base_dir: Path, cache_names: bool = False) -> dict:
    """Per-target provenance: source tree + deterministic artifact hashes."""
    state: dict = {}
    tree = TARGETS.get(name, {}).get("tree")
    if tree:
        state["tree_sha"] = tree_sha(REPO / tree)
    for key, bname, cname in _ARTIFACTS:
        state[f"{key}_sha"] = _records_sha(
            base_dir / (cname if cache_names else bname))
    return state


def collect_provenance(names: list[str]) -> dict:
    prov = {
        "version": BASELINE_VERSION,
        "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "git_rev": _git("rev-parse", "--short", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "semgrep": _tool_version(["semgrep", "--version"]),
        "joern": _joern_fingerprint(),
        "judge_scripts": {
            p: _sha256_file(REPO / p) for p in (
                "scripts/llm_judge_sink_chains.py",
                "scripts/llm_judge_entrypoints.py")},
        "engine_files": {str(p.relative_to(REPO)): _sha256_file(p)
                         for p in _engine_files()},
        "targets": {n: _target_state(n, BASELINE_DIR / n) for n in names},
    }
    prov.update(_model_env())
    return prov


def _read_baseline() -> dict:
    """Tolerate both layouts: v2 {version, provenance, targets} and the flat
    v1 {target: metrics} written before provenance existed."""
    if not BASELINE_FILE.exists():
        sys.exit(f"frozen baseline missing: {BASELINE_FILE}")
    data = json.loads(BASELINE_FILE.read_text())
    if "targets" in data and isinstance(data["targets"], dict):
        return data
    return {"version": 1, "provenance": {}, "targets": data}


def _classify(base_prov: dict, cur_prov: dict, name: str) -> list[str]:
    """Why the numbers may have moved, most significant first."""
    out: list[str] = []
    if not base_prov:
        return out
    for field in ("model", "base_url"):
        b, c = base_prov.get(field), cur_prov.get(field)
        if b and c and b != c:
            out.append(f"MODEL_DRIFT({field}: {b} -> {c})")
    b_eng, c_eng = base_prov.get("engine_files", {}), cur_prov.get("engine_files", {})
    changed = sorted(k for k in set(b_eng) | set(c_eng) if b_eng.get(k) != c_eng.get(k))
    if changed:
        out.append("ENGINE_CHANGED(" + ", ".join(changed[:3]) + ")")
    b_j, c_j = base_prov.get("judge_scripts", {}), cur_prov.get("judge_scripts", {})
    changed_j = sorted(k for k in set(b_j) | set(c_j) if b_j.get(k) != c_j.get(k))
    if changed_j:
        out.append("JUDGE_CHANGED(" + ", ".join(changed_j) + ")")
    b_t = (base_prov.get("targets") or {}).get(name, {})
    c_t = (cur_prov.get("targets") or {}).get(name, {})
    for key, label in (("tree_sha", "CODE_CHANGED"),
                       ("snippets_sha", "SNIPPET_CHANGED(A)"),
                       ("ep_snippets_sha", "SNIPPET_CHANGED(B)"),
                       ("chains_sha", "CHAINS_CHANGED")):
        b, c = b_t.get(key), c_t.get(key)
        if b and c and b != c:
            out.append(label)
    return out


def _confirmed_rate(name: str) -> tuple[int, int] | None:
    """(CONFIRMED, total) for the run under test, from its agent cache."""
    chains = AGENT_CACHE / name / "chains.jsonl"
    taint = AGENT_CACHE / name / "taint.jsonl"
    if not (chains.exists() and taint.exists()):
        return None
    sys.path.insert(0, str(REPO / "scripts"))
    import chain_report  # noqa: E402
    rep = chain_report.build_report(chain_report.load_jsonl(chains),
                                    chain_report.load_jsonl(taint))
    return chain_report.confirmed_rate(rep) if rep else None


def _leaks_since(ts: float) -> tuple[int, int]:
    """(#certain, #suspected) leak records newer than `ts` (epoch seconds)."""
    if not LEAK_AUDIT.exists():
        return (0, 0)
    certain = suspected = 0
    for line in LEAK_AUDIT.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        when = rec.get("ts_epoch")
        if when is None:  # pre-provenance records only carry a string ts
            try:
                when = time.mktime(time.strptime(rec.get("ts", ""),
                                                  "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                continue
        if when <= ts:
            continue
        if rec.get("severity") == "certain":
            certain += 1
        else:
            suspected += 1
    return (certain, suspected)


def run(cmd: list[str], env: dict | None = None, stdout_to: Path | None = None,
        timeout: int = 3600) -> None:
    """Run cmd (relative to repo root); raise on non-zero exit."""
    shown = " ".join(cmd)
    log(f"$ {shown}" + (f" > {stdout_to.name}" if stdout_to else ""))
    full_env = {**os.environ, **(env or {})}
    if stdout_to:
        with open(stdout_to, "w") as out:
            proc = subprocess.run(cmd, cwd=REPO, env=full_env, stdout=out,
                                  stderr=subprocess.PIPE, text=True, timeout=timeout)
    else:
        proc = subprocess.run(cmd, cwd=REPO, env=full_env, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, text=True, timeout=timeout)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise RuntimeError(f"command failed ({proc.returncode}): {shown}")
    # joern/semgrep progress goes to stderr; surface the last line as a hint
    hint = [ln for ln in proc.stderr.splitlines() if ln.strip()]
    if hint:
        log(f"  … {hint[-1][:200]}")


def step(done: Path, force: bool, fn, *args, **kwargs) -> None:
    """Run fn unless its `done` marker output already exists."""
    if done.exists() and not force:
        log(f"  skip (cached): {done.name}")
        return
    fn(*args, **kwargs)


def run_target(name: str, cfg: dict, force: bool, skip_llm: bool) -> dict:
    d = BASELINE_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    tree, rules, gt = cfg["tree"], cfg["rules"], cfg["ground_truth"]

    if cfg.get("pre"):
        run(cfg["pre"])

    raw = d / "semgrep_raw.json"
    step(raw, force, run,
         ["semgrep", "--config", rules, "--json", "--no-git-ignore",
          "-o", str(raw), tree])

    sinks = d / "sinks.json"
    step(sinks, force, run,
         ["python3", "scripts/semgrep_to_sinks.py", str(raw),
          "--root", tree, "-o", str(sinks)])

    cpg = d / "cpg.bin"
    step(cpg, force, run,
         [JOERN_PARSE, tree, "--output", str(cpg)], timeout=3600)

    chains = d / "chains.jsonl"
    step(chains, force, run,
         ["joern", "--script", "analysis/joern/backward_from_sinks.sc", str(cpg)],
         env={"SINKS_FILE": str(sinks), "CHAINS_JSON": str(chains)})

    taint = d / "taint.jsonl"
    step(taint, force, run,
         ["joern", "--script", "analysis/joern/taint_confirm.sc", str(cpg)],
         env={"SINKS_FILE": str(sinks)}, stdout_to=taint)

    report = d / "chain_report.jsonl"
    step(report, force, run,
         ["python3", "scripts/chain_report.py", "--chains", str(chains),
          "--taint", str(taint), "-o", str(report)])

    snippets = d / "snippets.jsonl"
    step(snippets, force, run,
         ["joern", "--script", "analysis/joern/extract_chain_snippets.sc", str(cpg)],
         env={"SINKS_FILE": str(sinks), "SRC_ROOT": tree}, stdout_to=snippets)

    ep_snippets = d / "ep_snippets.jsonl"
    step(ep_snippets, force, run,
         ["joern", "--script", "analysis/joern/extract_entrypoint_snippets.sc", str(cpg)],
         env={"SRC_ROOT": tree}, stdout_to=ep_snippets)

    if not skip_llm:
        verdicts_a = d / "verdicts_a.jsonl"
        summary_a = d / "judge_a_summary.txt"
        if not (verdicts_a.exists() and summary_a.exists()) or force:
            run(["uv", "run", "scripts/llm_judge_sink_chains.py",
                 "--snippets", str(snippets), "--ground-truth", gt,
                 "-o", str(verdicts_a)], stdout_to=summary_a, timeout=7200)

        verdicts_b = d / "verdicts_b.jsonl"
        summary_b = d / "judge_b_summary.txt"
        if not (verdicts_b.exists() and summary_b.exists()) or force:
            run(["uv", "run", "scripts/llm_judge_entrypoints.py",
                 "--snippets", str(ep_snippets), "--ground-truth", gt,
                 "-o", str(verdicts_b)], stdout_to=summary_b, timeout=7200)

    return collect_metrics(d)


def collect_metrics(d: Path) -> dict:
    """Recompute the summary numbers from on-disk artifacts."""
    metrics: dict = {"chains": {}, "judge_a": {}, "judge_b": {}}

    report = d / "chain_report.jsonl"
    if report.exists():
        counts = {"total": 0, "CONFIRMED": 0, "UNCONFIRMED": 0, "NO_CHAIN": 0}
        for line in report.read_text().splitlines():
            if line.strip().startswith("{"):
                counts["total"] += 1
                counts[json.loads(line)["status"]] = counts.get(json.loads(line)["status"], 0) + 1
        metrics["chains"] = counts

    for kind, fname, recall_key in (
        ("judge_a", "judge_a_summary.txt", "category A"),
        ("judge_b", "judge_b_summary.txt", "category B"),
    ):
        f = d / fname
        if not f.exists():
            continue
        text = f.read_text()
        m = {"recall": None, "safe_fp": [], "llm_errors": None}
        r = re.search(rf"Recall {re.escape(recall_key)}[^:]*:\s+(\S+)", text)
        if r:
            m["recall"] = r.group(1)
        fp = re.search(r"Safe-sample false positives[^:]*:\s+(.+)", text)
        if fp and fp.group(1).strip() != "none":
            m["safe_fp"] = json.loads(fp.group(1).strip().replace("'", '"'))
        t = re.search(r"TP=(\d+) FN=(\d+) FP=(\d+) TN=(\d+) LLM errors=(\d+)", text)
        if t:
            m.update(tp=int(t[1]), fn=int(t[2]), fp=int(t[3]), tn=int(t[4]),
                     llm_errors=int(t[5]))
        metrics[kind] = m
    return metrics


def _parse_recall(recall: str | None) -> tuple[int, int] | None:
    """'8/10' (optionally '= 80%') -> (8, 10); None when unparseable."""
    m = re.match(r"\s*(\d+)\s*/\s*(\d+)", recall or "")
    return (int(m[1]), int(m[2])) if m else None


def _is_b_summary(summary: dict) -> bool:
    results = summary.get("targets", summary)
    return any("recall_B" in r for r in results.values() if isinstance(r, dict))


def _latest_summary(b_mode: bool | None = None) -> Path:
    """Newest batch summary; with b_mode, the newest of that shape (A/B
    summaries are interleaved in the same directory)."""
    root = REPORT_ROOT
    candidates = sorted(root.glob("*/summary*.json"),
                        key=lambda p: p.stat().st_mtime)
    if b_mode is not None:
        same = [p for p in candidates
                if _is_b_summary(json.loads(p.read_text())) is b_mode]
        candidates = same
    if not candidates:
        sys.exit(f"no agent batch summary found under {root} "
                 "(run: uv run agent/run_agent.py --target all or "
                 "uv run agent/run_worker.py --target all)")
    return candidates[-1]


def _previous_summary(summary_path: Path, b_mode: bool) -> Path | None:
    """The batch summary immediately before `summary_path` of the same shape —
    the only honest token baseline, since the frozen judge baseline is a
    different pipeline (1 call per chain vs a full agent investigation)."""
    root = REPORT_ROOT
    same = [p for p in sorted(root.glob("*/summary*.json"),
                              key=lambda p: p.stat().st_mtime)
            if _is_b_summary(json.loads(p.read_text())) is b_mode]
    prior = [p for p in same if p.stat().st_mtime < summary_path.stat().st_mtime]
    return prior[-1] if prior else None


def compare_with_baseline(summary_path: Path, *, require_baseline: bool = False,
                          max_token_delta: float | None = None,
                          cost_baseline: Path | None = None,
                          min_confirmed_rate: float | None = None,
                          forbid_leak: bool = False) -> int:
    """M5/M8 regression gate, extended with provenance + budget dimensions.

    Auto-detects the summary shape — A-class summary.json (run_agent) or
    B-class summary_b.json (run_worker). Per target: FAIL on a recall drop
    below the frozen baseline, a NEW safe-sample FP, a confirmed-rate floor,
    a token overrun vs the previous batch of the same shape, or a recorded
    ground-truth leak. SKIP (never a regression) when the comparison is not
    possible — a target frozen with --skip-llm has no judge baseline, and
    `require_baseline` promotes those to FAIL."""
    baseline = _read_baseline()
    base_targets = baseline["targets"]
    base_prov = baseline.get("provenance") or {}
    summary = json.loads(summary_path.read_text())
    results = summary.get("targets", summary)  # tolerate a bare target dict

    b_mode = _is_b_summary(summary)
    judge_key = "judge_b" if b_mode else "judge_a"
    recall_hit_key = "recall_B_hit" if b_mode else "recall_A_hit"
    recall_str_key = "recall_B" if b_mode else "recall_A"
    fp_key = "safe_fp_b" if b_mode else "safe_fp"
    label = "B" if b_mode else "A"

    # provenance of the run under test: same helpers, agent-cache artifacts
    cur_prov = dict(base_prov)
    cur_prov.update(_model_env())
    cur_prov["engine_files"] = {str(p.relative_to(REPO)): _sha256_file(p)
                                for p in _engine_files()}
    cur_prov["judge_scripts"] = {
        p: _sha256_file(REPO / p) for p in (
            "scripts/llm_judge_sink_chains.py",
            "scripts/llm_judge_entrypoints.py")}
    cur_prov["targets"] = {
        n: _target_state(n, AGENT_CACHE / n, cache_names=True)
        for n in results if (AGENT_CACHE / n).exists()}

    # token dimension: vs the previous batch of the same shape
    cost_ref = cost_baseline
    if max_token_delta is not None and cost_ref is None:
        cost_ref = _previous_summary(summary_path, b_mode)
    cost_tokens = (json.loads(cost_ref.read_text()).get("targets", {})
                   if cost_ref else {})

    log(f"comparing {summary_path} ({label}-class) against {BASELINE_FILE}")
    if max_token_delta is not None:
        log(f"cost baseline: {cost_ref or 'none (cost dimension skipped)'}")

    failed = skipped = 0
    print(f"\n{'target':<24} {f'{label} recall (agent vs baseline)':<30} "
          f"{'safe FP':<26} {'gate':<6} why")
    for name, res in results.items():
        base = base_targets.get(name)
        why: list[str] = []
        if base is None:
            status, why = ("FAIL", ["no baseline entry"])
        elif "error" in res:
            status, why = ("FAIL", [f"run error: {str(res['error'])[:60]}"])
        else:
            core_fail = False
            b_recall = _parse_recall(base.get(judge_key, {}).get("recall"))
            hit = res.get(recall_hit_key)
            recall_txt = (f"{res.get(recall_str_key, '?')} vs "
                          f"{base.get(judge_key, {}).get('recall', '?')}")
            if b_recall is None:
                # no comparable baseline for this class (--skip-llm freeze)
                status = "FAIL" if require_baseline else "SKIP"
                why = [f"no {judge_key} baseline"]
            elif hit is None:
                status, why = "SKIP", ["no recall in summary"]
            elif hit < b_recall[0]:
                status = "FAIL"
                core_fail = True
                why = [f"{label} recall dropped {b_recall[0]} -> {hit}"]
            else:
                status = "PASS"

            known_fp = set(base.get("judge_a", {}).get("safe_fp", []))
            known_fp |= set(base.get("judge_b", {}).get("safe_fp", []))
            new_fp = [f for f in (res.get(fp_key) or []) if f not in known_fp]
            fp_txt = str(res.get(fp_key) or [])[:24]
            if new_fp and status != "SKIP":
                status = "FAIL"
                core_fail = True
                why.append(f"new safe FP: {new_fp}")
            elif new_fp:
                why.append(f"new safe FP (uncompared): {new_fp}")

            # confirmed-rate floor (deterministic stage of the run under test)
            if min_confirmed_rate is not None:
                rate = _confirmed_rate(name)
                if rate is None:
                    why.append("confirmed rate: no agent cache")
                    if status == "PASS":
                        status = "SKIP"
                else:
                    confirmed, total = rate
                    frac = confirmed / total if total else 0.0
                    why.append(f"confirmed {confirmed}/{total} = {frac:.0%}")
                    if frac < min_confirmed_rate:
                        status = "FAIL"
                        why.append(f"below floor {min_confirmed_rate:.0%}")

            # token budget vs the previous batch of the same shape
            if max_token_delta is not None and status != "SKIP":
                ref = cost_tokens.get(name, {}) if cost_tokens else {}
                cur_tok, ref_tok = res.get("tokens"), ref.get("tokens")
                if cur_tok and ref_tok:
                    drift = (cur_tok - ref_tok) / ref_tok
                    why.append(f"tokens {cur_tok/1e6:.2f}M vs "
                               f"{ref_tok/1e6:.2f}M ({drift:+.0%})")
                    if drift > max_token_delta:
                        status = "FAIL"
                        why.append(f"over +{max_token_delta:.0%} budget")
                else:
                    why.append("tokens: no comparable pair (skipped)")

            why += _classify(base_prov, cur_prov, name)
            # REAL_REGRESSION is reserved for the core dimensions: a budget
            # overrun or a missing measurement is not a quality regression
            if core_fail and not any(
                    w.startswith(("MODEL_DRIFT", "CODE_CHANGED",
                                  "SNIPPET_CHANGED", "ENGINE_CHANGED",
                                  "CHAINS_CHANGED", "JUDGE_CHANGED"))
                    for w in why):
                why.append("REAL_REGRESSION")

        failed += status == "FAIL"
        skipped += status == "SKIP"
        recall_txt = (f"{res.get(recall_str_key, '—')} vs "
                      f"{base.get(judge_key, {}).get('recall', '—')}"
                      if base else "—")
        fp_txt = str((res.get(fp_key) if base else None) or [])[:24]
        print(f"{name:<24} {recall_txt:<30} {fp_txt:<26} {status:<6} "
              + ("; ".join(why) if why else ""))

    if forbid_leak:
        certain, suspected = _leaks_since(summary_path.stat().st_mtime)
        verdict = "FAIL" if certain else "PASS"
        print(f"\nleak audit since summary: {certain} certain, "
              f"{suspected} suspected -> {verdict}")
        if certain:
            failed += 1

    absent = [n for n in base_targets if n not in results]
    if absent:
        print(f"\nnot in this summary: {', '.join(sorted(absent))}")
    print(f"\nGATE: {'FAIL' if failed else 'PASS'}"
          + (f"  ({failed} failed, {skipped} skipped)" if skipped or failed else ""))
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default=",".join(TARGETS),
                    help="comma-separated subset of targets")
    ap.add_argument("--skip-llm", action="store_true",
                    help="run only the deterministic stages (no LLM judges)")
    ap.add_argument("--force", action="store_true",
                    help="redo steps even when cached artifacts exist")
    ap.add_argument("--collect-only", action="store_true",
                    help="only recompute baseline.json from existing artifacts")
    ap.add_argument("--compare", nargs="?", const="", default=None,
                    metavar="SUMMARY_JSON",
                    help="M5/M8 regression gate: compare an agent batch "
                         "summary.json (A-class) or summary_b.json "
                         "(B-class) (default: latest under "
                         "workspace/agent-reports/) against the frozen "
                         "baseline; non-zero exit on recall drop or new "
                         "safe-sample FP")
    gate = ap.add_argument_group(
        "gate dimensions",
        "Each dimension that cannot be evaluated prints SKIP instead of "
        "failing; a target with no judge baseline is never a regression "
        "unless --require-baseline.")
    gate.add_argument("--require-baseline", action="store_true",
                      help="treat SKIP (missing baseline) as FAIL")
    gate.add_argument("--max-token-delta", type=float, default=None,
                      metavar="PCT",
                      help="fail when tokens exceed the previous batch of "
                           "the same shape by more than PCT percent "
                           "(default: off)")
    gate.add_argument("--cost-baseline", default="",
                      metavar="SUMMARY_JSON",
                      help="summary to compare tokens against (default: the "
                           "previous same-shape summary)")
    gate.add_argument("--min-confirmed-rate", type=float, default=None,
                      metavar="PCT",
                      help="fail when the run's CONFIRMED/total chain rate "
                           "falls below PCT (default: off)")
    gate.add_argument("--forbid-leak", action="store_true",
                      help="fail if any certain ground-truth leak is "
                           "recorded in workspace/leak-audit.jsonl after "
                           "the summary was written")
    args = ap.parse_args()

    if args.compare is not None:
        path = Path(args.compare) if args.compare else _latest_summary()
        return compare_with_baseline(
            path,
            require_baseline=args.require_baseline,
            max_token_delta=args.max_token_delta,
            cost_baseline=Path(args.cost_baseline) if args.cost_baseline else None,
            min_confirmed_rate=args.min_confirmed_rate,
            forbid_leak=args.forbid_leak)

    names = [n.strip() for n in args.targets.split(",") if n.strip()]
    unknown = [n for n in names if n not in TARGETS]
    if unknown:
        sys.exit(f"unknown targets: {unknown} (known: {list(TARGETS)})")

    summary = {}
    for name in names:
        log(f"=== target: {name} ===")
        try:
            if args.collect_only:
                summary[name] = collect_metrics(BASELINE_DIR / name)
            else:
                summary[name] = run_target(name, TARGETS[name],
                                           args.force, args.skip_llm)
        except Exception as e:  # keep going, record the failure
            log(f"!!! {name} FAILED: {e}")
            summary[name] = {"error": str(e)}

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    # v2 layout {version, provenance, targets}; a v1 flat file is migrated on
    # read, so single-target reruns keep every other target's metrics.
    existing = _read_baseline()
    existing["version"] = BASELINE_VERSION
    existing["targets"].update(summary)
    # provenance is re-stamped for the targets this run touched; untouched
    # targets keep their hashes so a partial re-freeze stays comparable.
    prov = existing.get("provenance") or {}
    prov.setdefault("targets", {})
    prov.update({k: v for k, v in collect_provenance(list(summary)).items()
                 if k != "targets"})
    prov["targets"].update({n: _target_state(n, BASELINE_DIR / n) for n in summary})
    prov["version"] = BASELINE_VERSION
    # drop entries for targets that are no longer registered (e.g. the
    # removed jsp-legacy) — they can never be compared, and a stale key only
    # prints as noise.
    for stale in [n for n in existing["targets"] if n not in TARGETS]:
        log(f"pruning baseline entry for unregistered target: {stale}")
        del existing["targets"][stale]
        prov["targets"].pop(stale, None)
    existing["provenance"] = prov
    BASELINE_FILE.write_text(json.dumps(existing, indent=2) + "\n")
    log(f"baseline written to {BASELINE_FILE}")

    for name, m in summary.items():
        ch, ja, jb = m.get("chains", {}), m.get("judge_a", {}), m.get("judge_b", {})
        print(f"{name:<15} chains {ch.get('CONFIRMED', '-')}/{ch.get('total', '-')}"
              f" CONFIRMED | A recall {ja.get('recall', '-')} FP {ja.get('safe_fp', '-')}"
              f" | B recall {jb.get('recall', '-')} FP {jb.get('safe_fp', '-')}")
    return 1 if any("error" in m for m in summary.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
