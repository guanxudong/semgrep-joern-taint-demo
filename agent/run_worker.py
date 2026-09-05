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
"""Category-B worker CLI (AGENT_MVP_PLAN.md §7A, milestone M7).

Consumes the planner's hypothesis queue
(workspace/agent-cache/<target>/hypotheses.jsonl — run
`uv run --offline agent/run_planner.py --target <name>` first), runs the
absence-comparison worker over each hypothesis, then the attacker/defender
adversarial review for every vulnerable verdict, and writes
workspace/agent-reports/<date>-m7/<target>/{findings_b.jsonl,report_b.md}
plus a ground-truth score summary on stdout (ground truth is read ONLY in
the finalize step, by the scorer — never by agent tools, red line §9.2).

Usage:
    uv run --offline agent/run_worker.py --target python-flask
    uv run --offline agent/run_worker.py --target python-flask --limit 3
    uv run --offline agent/run_worker.py --target python-flask --no-verify
    uv run --offline agent/run_worker.py --target all   # sequential batch
    uv run --offline agent/run_worker.py --target python-flask --dry-run

--dry-run skips all LLM calls (stub not-vulnerable findings) and exercises
only the queue loading + finalize/scoring path.
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # for the sast_agent package

from sast_agent import config  # noqa: E402
from sast_agent import pipeline  # noqa: E402
from sast_agent import report as report_mod  # noqa: E402
from sast_agent.contracts import BFinding, Hypothesis, Verdict  # noqa: E402
from sast_agent.tools import SastTools  # noqa: E402
from sast_agent.verifier import verify_b_finding  # noqa: E402
from sast_agent.worker import investigate_hypothesis  # noqa: E402

REPORTS_ROOT = config.REPO / "workspace" / "agent-reports"


def log(msg: str) -> None:
    print(f"[run_worker] {msg}", file=sys.stderr, flush=True)


def load_hypotheses(target: str) -> list[Hypothesis]:
    """The planner's queue for one target; missing -> tell the user to run
    the planner first (the queue is M6's output)."""
    path = config.cache_dir(target) / "hypotheses.jsonl"
    if not path.is_file() or not path.read_text().strip():
        sys.exit(f"no hypothesis queue at {path} — run "
                 f"`uv run --offline agent/run_planner.py --target {target}` "
                 "first")
    hyps = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            hyps.append(Hypothesis.model_validate_json(line))
    return hyps


def _dry_run_finding(hyp: Hypothesis) -> BFinding:
    """Stub finding for --dry-run: not vulnerable, no LLM involved."""
    return BFinding(
        hypothesis=hyp,
        verdict=Verdict(is_vulnerable=False, confidence=0.1,
                        reasoning="dry run: investigation skipped"),
        confidence_level="SUSPICIOUS",
        evidence=[],
        stats={"tool_calls": 0, "tokens": 0, "requests": 0, "seconds": 0.0,
               "budget_hit": False, "timeout_hit": False,
               "status": "dry_run", "tool_log": []},
    )


async def run_target(target: str, limit: int, no_verify: bool = False,
                     dry_run: bool = False,
                     out_root: Path | None = None) -> dict:
    hypotheses = load_hypotheses(target)
    if limit:
        hypotheses = hypotheses[:limit]
    log(f"{target}: {len(hypotheses)} hypotheses to investigate "
        f"(concurrency {config.WORKER_CONCURRENCY})")

    tools = SastTools(target, config.cache_dir(target))
    tree_path = config.target_cfg(target)["tree_path"]

    out_dir = (out_root or REPORTS_ROOT) / target
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings_b.jsonl"

    if not dry_run:
        # warm the entrypoint-snippet cache sequentially: the first cold
        # joern subprocess would otherwise block the event loop inside a
        # parallel task
        pipeline.get_entrypoint_snippets(target)

    total_tokens = 0
    sem = asyncio.Semaphore(config.WORKER_CONCURRENCY)

    async def one(i: int, hyp: Hypothesis, fh) -> None:
        nonlocal total_tokens
        async with sem:
            if dry_run:
                finding = _dry_run_finding(hyp)
            else:
                remaining = config.WORKER_TOTAL_LLM_TOKENS - total_tokens
                finding = await investigate_hypothesis(
                    hyp, tools, token_budget=max(remaining, 0))
                total_tokens += finding.stats.get("tokens", 0)
            verifier_note = ""
            # B-class adversarial review (§7A): vulnerable verdicts only
            if finding.verdict.is_vulnerable and not (no_verify or dry_run):
                remaining = config.WORKER_TOTAL_LLM_TOKENS - total_tokens
                vres = await verify_b_finding(finding, tools,
                                              token_budget=max(remaining, 0))
                fd = report_mod.apply_verifier_b(finding.model_dump(), vres,
                                                 tree_path)
                finding = BFinding.model_validate(fd)
                total_tokens += vres.get("tokens", 0)
                vst = vres.get("status", {})
                verifier_note = (
                    f" | verifier att={vst.get('attacker', '?')} "
                    f"def={vst.get('defender', '?')} "
                    f"veto={finding.stats.get('verifier', {}).get('veto')} "
                    f"-> {finding.confidence_level}")
            fh.write(finding.model_dump_json() + "\n")
            fh.flush()
            log(f"  [{i}/{len(hypotheses)}] {hyp.vuln_type} {hyp.route} -> "
                f"vuln={finding.verdict.is_vulnerable} "
                f"({finding.confidence_level}, "
                f"{finding.stats['tool_calls']} calls, "
                f"{finding.stats['tokens']} tokens, {finding.stats['seconds']}s, "
                f"{finding.stats['status']})" + verifier_note)

    with open(findings_path, "w") as fh:
        await asyncio.gather(
            *(one(i, hyp, fh) for i, hyp in enumerate(hypotheses, 1)))
    log(f"findings written to {findings_path} (total {total_tokens} tokens)")
    return {"out_dir": out_dir, "tokens": total_tokens}


def finalize_target_b(target: str, out_dir: Path) -> dict:
    """Post-run tail: §6A validation layer with the category-B rule
    (rewrites findings_b.jsonl), then ground-truth scoring + report_b.md
    rendering. Ground truth is read ONLY here. Returns the score dict."""
    findings = report_mod.load_findings(str(out_dir / "findings_b.jsonl"))
    cfg = config.target_cfg(target)
    findings = report_mod.apply_validation(findings, cfg["tree_path"],
                                           b_class=True)
    with open(out_dir / "findings_b.jsonl", "w") as fh:
        for f in findings:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")
    with open(cfg["ground_truth"]) as f:
        ground_truth = json.load(f)
    score = report_mod.score_b_findings(findings, ground_truth)
    # M8: planner's taxonomy coverage checklist (cache, no GT) -> audit section
    cov_path = config.cache_dir(target) / "taxonomy_checklist.json"
    checklist = json.loads(cov_path.read_text()) if cov_path.exists() else None
    md = report_mod.render_markdown_b(findings, score, checklist)
    report_path = out_dir / "report_b.md"
    report_path.write_text(md + "\n")
    log(f"report written to {report_path}")
    return score


def _date_out_root() -> Path:
    """workspace/agent-reports/<date>-m7/ (suffixed with the time when a
    run already landed there today, so same-day reruns don't clobber and
    B-class outputs never mix with the A-class <date>/ dirs)."""
    root = REPORTS_ROOT / (time.strftime("%Y-%m-%d") + "-m7")
    if (root / "summary_b.json").exists():
        root = REPORTS_ROOT / (time.strftime("%Y-%m-%d-%H%M%S") + "-m7")
    return root


def run_all(limit: int, no_verify: bool, dry_run: bool,
            exclude: list[str] | None = None) -> int:
    """Batch mode: every target, sequential (14-18 hypotheses per target,
    fewer than A-class sinks — simple and reliable), plus an aggregate
    summary_b.json. `exclude` skips targets (e.g. ["csharp-aspnet"])."""
    names = [n for n in config.TARGETS if n not in (exclude or [])]
    out_root = _date_out_root()
    log(f"batch mode: {len(names)} targets, sequential -> {out_root}")

    summary: dict = {"date": out_root.name, "targets": {}}
    failed = False
    for name in names:
        try:
            result = asyncio.run(run_target(name, limit, no_verify, dry_run,
                                            out_root=out_root))
        except Exception as e:  # keep the other targets going
            log(f"!!! {name} FAILED: {e}")
            summary["targets"][name] = {"error": str(e)}
            failed = True
            continue
        score = finalize_target_b(name, result["out_dir"])
        summary["targets"][name] = {
            "recall_B": score["recall_B"],
            "recall_B_hit": score["recall_B_hit"],
            "recall_B_total": score["recall_B_total"],
            "safe_fp_b": score["safe_fp_b"],
            "tp": score["tp"], "fn": score["fn"],
            "fp": score["fp"], "tn": score["tn"],
            "tokens": result["tokens"],
            "report": str(result["out_dir"] / "report_b.md"),
        }
        print(f"\n=== {name} ===")
        print(report_mod.summary_text_b(score))
    out_root.mkdir(parents=True, exist_ok=True)
    summary_path = out_root / "summary_b.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    log(f"summary written to {summary_path}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True,
                    choices=list(config.TARGETS) + ["all"])
    ap.add_argument("--limit", type=int, default=0,
                    help="investigate only the first N hypotheses (smoke test)")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the adversarial review (attacker/defender)")
    ap.add_argument("--dry-run", action="store_true",
                    help="no LLM calls: stub findings, exercise queue loading "
                         "and the finalize/scoring path only")
    ap.add_argument("--exclude", default="",
                    help="comma-separated targets to skip in --target all "
                         "(e.g. --exclude csharp-aspnet)")
    args = ap.parse_args()

    if not config.API_KEY and not args.dry_run:
        sys.exit("DEEPSEEK_API_KEY not set (env, ./.env, or ~/Code/agent-demo/.env)")

    exclude = [s for s in args.exclude.split(",") if s]
    unknown = [s for s in exclude if s not in config.TARGETS]
    if unknown:
        sys.exit(f"unknown targets in --exclude: {unknown}")

    if args.target == "all":
        return run_all(args.limit, args.no_verify, args.dry_run, exclude)

    out_root = _date_out_root()
    result = asyncio.run(run_target(args.target, args.limit, args.no_verify,
                                    args.dry_run, out_root=out_root))
    score = finalize_target_b(args.target, result["out_dir"])
    print(report_mod.summary_text_b(score))
    return 0


if __name__ == "__main__":
    sys.exit(main())
