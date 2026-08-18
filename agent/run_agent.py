#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pydantic-ai-slim[openai]>=2.0.0",
#     "pydantic>=2",
#     "python-dotenv>=1.0.0",
#     "httpx[socks]>=0.27",
# ]
# ///
"""AI SAST agent CLI (AGENT_MVP_PLAN.md §2, milestones M2–M5).

Runs the deterministic screening (pipeline.screen), then the per-sink
investigation agent over each InvestigationBrief, then (M4) the
attacker/defender adversarial review for every vulnerable verdict, and
writes workspace/agent-reports/<target>/{findings.jsonl,report.md} plus a
ground-truth score summary on stdout.

Usage:
    uv run agent/run_agent.py --target python-flask
    uv run agent/run_agent.py --target python-flask --limit 3   # smoke
    uv run agent/run_agent.py --target python-flask --no-verify # skip M4 review
    uv run agent/run_agent.py --target all                      # M5 batch mode

M5 batch mode (--target all, plan §8-M5): runs every target with
parallelism 2 (joern is memory-hungry — do not raise), writes reports to
workspace/agent-reports/<date>/<target>/ and an aggregate summary.json to
workspace/agent-reports/<date>/; gate it with
`python3 agent/run_baseline.py --compare`.
"""

import argparse
import asyncio
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # for the sast_agent package

from sast_agent import config, pipeline  # noqa: E402
from sast_agent import report as report_mod  # noqa: E402
from sast_agent.contracts import Finding  # noqa: E402
from sast_agent.investigator import investigate_sink  # noqa: E402
from sast_agent.tools import SastTools  # noqa: E402
from sast_agent.verifier import verify_finding  # noqa: E402

REPORTS_ROOT = config.REPO / "workspace" / "agent-reports"


def log(msg: str) -> None:
    print(f"[run_agent] {msg}", file=sys.stderr, flush=True)


async def run_target(target: str, limit: int, only_sink: str = "",
                     no_verify: bool = False,
                     out_root: Path | None = None) -> dict:
    briefs = pipeline.screen(target)
    if only_sink:
        briefs = [b for b in briefs if only_sink in b.sink.id]
    if limit:
        briefs = briefs[:limit]
    log(f"{target}: {len(briefs)} sinks to investigate "
        f"({sum(1 for b in briefs if b.gap.value != 'OK')} with gaps)")

    tools = SastTools(target, config.cache_dir(target))
    tree_path = config.target_cfg(target)["tree_path"]

    out_dir = (out_root or REPORTS_ROOT) / target
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.jsonl"

    total_tokens = 0
    with open(findings_path, "w") as fh:
        for i, brief in enumerate(briefs, 1):
            remaining = config.MAX_TOTAL_LLM_TOKENS - total_tokens
            finding = await investigate_sink(brief, tools,
                                             token_budget=max(remaining, 0))
            total_tokens += finding.stats.get("tokens", 0)
            verifier_note = ""
            # M4 (plan §7): adversarial review on vulnerable verdicts only
            if finding.verdict.is_vulnerable and not no_verify:
                remaining = config.MAX_TOTAL_LLM_TOKENS - total_tokens
                vres = await verify_finding(finding, tools,
                                            token_budget=max(remaining, 0))
                fd = report_mod.apply_verifier(finding.model_dump(), vres,
                                               tree_path)
                finding = Finding.model_validate(fd)
                total_tokens += vres.get("tokens", 0)
                vst = vres.get("status", {})
                verifier_note = (
                    f" | verifier att={vst.get('attacker', '?')} "
                    f"def={vst.get('defender', '?')} "
                    f"veto={finding.stats.get('verifier', {}).get('veto')} "
                    f"-> {finding.confidence_level}")
            fh.write(finding.model_dump_json() + "\n")
            fh.flush()
            log(f"  [{i}/{len(briefs)}] {brief.sink.id} gap={brief.gap.value} -> "
                f"vuln={finding.verdict.is_vulnerable} "
                f"({finding.confidence_level}, "
                f"{finding.stats['tool_calls']} calls, "
                f"{finding.stats['tokens']} tokens, {finding.stats['seconds']}s, "
                f"{finding.stats['status']})" + verifier_note)
    log(f"findings written to {findings_path} "
        f"(total {total_tokens} tokens)")
    return {"out_dir": out_dir, "tokens": total_tokens}


def finalize_target(target: str, out_dir: Path) -> dict:
    """Post-run tail: §6A validation layer (rewrites findings.jsonl), then
    ground-truth scoring + report.md rendering. Returns the score dict."""
    findings = report_mod.load_findings(str(out_dir / "findings.jsonl"))
    cfg = config.target_cfg(target)
    findings = report_mod.apply_validation(findings, cfg["tree_path"])
    with open(out_dir / "findings.jsonl", "w") as fh:
        for f in findings:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
    with open(cfg["ground_truth"]) as f:
        ground_truth = json.load(f)
    score = report_mod.score_findings(findings, ground_truth)
    md = report_mod.render_markdown(findings, score)
    report_path = out_dir / "report.md"
    report_path.write_text(md + "\n")
    log(f"report written to {report_path}")
    return score


def _date_out_root() -> Path:
    """workspace/agent-reports/<date>/ (suffixed with the time when a run
    already landed there today, so same-day reruns don't clobber)."""
    root = REPORTS_ROOT / time.strftime("%Y-%m-%d")
    if (root / "summary.json").exists():
        root = REPORTS_ROOT / time.strftime("%Y-%m-%d-%H%M%S")
    return root


def run_all(limit: int, only_sink: str, no_verify: bool) -> int:
    """M5 batch mode: every target, parallelism 2 (joern memory), reports
    under workspace/agent-reports/<date>/ plus an aggregate summary.json
    consumed by `run_baseline.py --compare`."""
    names = list(config.TARGETS)
    out_root = _date_out_root()
    log(f"batch mode: {len(names)} targets, parallelism 2 -> {out_root}")

    def one(name: str) -> dict:
        return asyncio.run(run_target(name, limit, only_sink, no_verify,
                                      out_root=out_root))

    runs: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(one, name): name for name in names}
        for fut in futures:
            name = futures[fut]
            try:
                runs[name] = {"run": fut.result()}
            except Exception as e:  # keep the other targets going
                log(f"!!! {name} FAILED: {e}")
                runs[name] = {"error": str(e)}

    summary: dict = {"date": out_root.name, "targets": {}}
    failed = False
    for name in names:  # stable order, scoring is cheap and sequential
        entry = runs[name]
        if "error" in entry:
            failed = True
            summary["targets"][name] = {"error": entry["error"]}
            continue
        score = finalize_target(name, entry["run"]["out_dir"])
        summary["targets"][name] = {
            "recall_A": score["recall_A"],
            "recall_A_hit": score["recall_A_hit"],
            "recall_A_total": score["recall_A_total"],
            "safe_fp": score["safe_fp"],
            "tp": score["tp"], "fn": score["fn"],
            "fp": score["fp"], "tn": score["tn"],
            "tokens": entry["run"]["tokens"],
            "report": str(entry["run"]["out_dir"] / "report.md"),
        }
        print(f"\n=== {name} ===")
        print(report_mod.summary_text(score))
    out_root.mkdir(parents=True, exist_ok=True)
    summary_path = out_root / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    log(f"summary written to {summary_path}")
    log("gate: python3 agent/run_baseline.py --compare "
        f"{summary_path.relative_to(config.REPO)}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True,
                    choices=list(config.TARGETS) + ["all"],
                    help="benchmark target name, or 'all' for M5 batch mode")
    ap.add_argument("--limit", type=int, default=0,
                    help="investigate only the first N sinks (smoke test)")
    ap.add_argument("--only-sink", default="",
                    help="investigate only sinks whose id contains this substring")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the M4 adversarial review (attacker/defender)")
    args = ap.parse_args()

    if not config.API_KEY:
        sys.exit("DEEPSEEK_API_KEY not set (env, ./.env, or ~/Code/agent-demo/.env)")

    if args.target == "all":
        return run_all(args.limit, args.only_sink, args.no_verify)

    result = asyncio.run(run_target(args.target, args.limit, args.only_sink,
                                    args.no_verify))
    score = finalize_target(args.target, result["out_dir"])
    print(report_mod.summary_text(score))
    return 0


if __name__ == "__main__":
    sys.exit(main())
