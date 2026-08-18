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
    python3 agent/run_baseline.py --targets python-flask,jsp-legacy
    python3 agent/run_baseline.py --skip-llm           # deterministic stages only
    python3 agent/run_baseline.py --force              # redo cached artifacts
    python3 agent/run_baseline.py --compare [summary.json]  # M5 regression gate

M5 regression gate (--compare, plan §8-M5): compares an agent batch run's
summary.json (default: the latest workspace/agent-reports/*/summary.json)
against this frozen baseline. Exit code is non-zero when any compared
target's category-A recall drops below the baseline or a NEW safe-sample
false positive appears (FP ids already present in the baseline are
tolerated). Baseline-recording flags are ignored in compare mode.

Every step is skipped when its output already exists (unless --force), so
re-runs are cheap and a crash can be resumed.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE_DIR = REPO / "workspace" / "baseline"


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
    # JSP is analyzed via the transpiled Java tree (D9): the whole java
    # pipeline runs on workspace/jsp-java.
    "jsp-legacy": {
        "rules": "analysis/rules/sinks-java.yml",
        "tree": "workspace/jsp-java",
        "ground_truth": "targets/jsp-legacy/ground_truth.json",
        "pre": ["python3", "scripts/jsp_to_java.py", "targets/jsp-legacy"],
    },
}


def log(msg: str) -> None:
    print(f"[baseline {time.strftime('%H:%M:%S')}] {msg}", flush=True)


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

    # --no-git-ignore: the JSP pipeline scans workspace/jsp-java (gitignored)
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
    return (int(m.group(1)), int(m.group(2))) if m else None


def _latest_summary() -> Path:
    root = REPO / "workspace" / "agent-reports"
    candidates = sorted(root.glob("*/summary.json"),
                        key=lambda p: p.stat().st_mtime)
    if not candidates:
        sys.exit(f"no agent batch summary found under {root} "
                 f"(run: uv run agent/run_agent.py --target all)")
    return candidates[-1]


def compare_with_baseline(summary_path: Path) -> int:
    """M5 regression gate (plan §8-M5): agent batch summary vs the frozen
    baseline. Fails (exit 1) on A-recall drop or a NEW safe-sample FP."""
    baseline_file = BASELINE_DIR / "baseline.json"
    if not baseline_file.exists():
        sys.exit(f"frozen baseline missing: {baseline_file}")
    baseline = json.loads(baseline_file.read_text())
    summary = json.loads(summary_path.read_text())
    results = summary.get("targets", summary)  # tolerate a bare target dict

    log(f"comparing {summary_path} against {baseline_file}")
    failed = False
    print(f"\n{'target':<15} {'A recall (agent vs baseline)':<30} "
          f"{'safe FP':<28} gate")
    for name, res in results.items():
        base = baseline.get(name)
        if base is None:
            failed = True
            print(f"{name:<15} {'—':<30} {'—':<28} FAIL (no baseline)")
            continue
        if "error" in res:
            failed = True
            print(f"{name:<15} {'—':<30} {'—':<28} FAIL (run error)")
            continue

        reasons = []
        b_recall = _parse_recall(base.get("judge_a", {}).get("recall"))
        a_hit = res.get("recall_A_hit")
        recall_txt = f"{res.get('recall_A', '?')} vs {base.get('judge_a', {}).get('recall', '?')}"
        if b_recall is None or a_hit is None:
            reasons.append("recall unparseable")
        elif a_hit < b_recall[0]:
            reasons.append(f"A recall dropped {b_recall[0]} -> {a_hit}")

        known_fp = set(base.get("judge_a", {}).get("safe_fp", []))
        known_fp |= set(base.get("judge_b", {}).get("safe_fp", []))
        new_fp = [f for f in res.get("safe_fp", []) if f not in known_fp]
        fp_txt = str(res.get("safe_fp") or [])[:26]
        if new_fp:
            reasons.append(f"new safe FP: {new_fp}")

        failed = failed or bool(reasons)
        print(f"{name:<15} {recall_txt:<30} {fp_txt:<28} "
              + ("FAIL: " + "; ".join(reasons) if reasons else "PASS"))

    skipped = [n for n in baseline if n not in results]
    if skipped:
        print(f"\nskipped (not in summary): {', '.join(skipped)}")
    print("\nGATE:", "FAIL" if failed else "PASS")
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
                    help="M5 regression gate: compare an agent batch "
                         "summary.json (default: latest under "
                         "workspace/agent-reports/) against the frozen "
                         "baseline; non-zero exit on recall drop or new "
                         "safe-sample FP")
    args = ap.parse_args()

    if args.compare is not None:
        path = Path(args.compare) if args.compare else _latest_summary()
        return compare_with_baseline(path)

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
    out = BASELINE_DIR / "baseline.json"
    # merge into any existing baseline so single-target reruns don't drop others
    merged: dict = {}
    if out.exists():
        try:
            merged = json.loads(out.read_text())
        except json.JSONDecodeError:
            pass
    merged.update(summary)
    out.write_text(json.dumps(merged, indent=2) + "\n")
    log(f"baseline written to {out}")

    for name, m in summary.items():
        ch, ja, jb = m.get("chains", {}), m.get("judge_a", {}), m.get("judge_b", {})
        print(f"{name:<15} chains {ch.get('CONFIRMED', '-')}/{ch.get('total', '-')}"
              f" CONFIRMED | A recall {ja.get('recall', '-')} FP {ja.get('safe_fp', '-')}"
              f" | B recall {jb.get('recall', '-')} FP {jb.get('safe_fp', '-')}")
    return 1 if any("error" in m for m in summary.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
