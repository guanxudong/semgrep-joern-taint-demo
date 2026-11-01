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
"""Tracer CLI (A-class): LLM-guided trace-continuation state machine.

Screening and post-processing mirror the deterministic pipeline
(pipeline.screen -> findings.jsonl -> mechanical validation layer ->
ground-truth scoring -> report.md), but the per-sink investigation is the
tracer state machine (sast_agent/tracer.py): the orchestrator owns the
TraceState dossier and executes every engine step; the LLM answers one
structured TraceStep per round from a closed directive menu, plus one
structured verdict at the end.

Usage:
    uv run --offline agent/run_trace.py --target python-flask
    uv run --offline agent/run_trace.py --target all          # batch, parallelism 2
    uv run --offline agent/run_trace.py --target all --dry-run  # zero-LLM smoke

Reports land in workspace/agent-reports/<date>-trace/<target>/ (batch) or
workspace/agent-reports/<target>-trace/ (single target). Gate with
`python3 agent/run_baseline.py --compare <summary.json>`.
"""

import argparse
import asyncio
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # for the sast_agent package

from sast_agent import config, pipeline, tracer  # noqa: E402
from sast_agent import report as report_mod  # noqa: E402
from sast_agent.contracts import Finding  # noqa: E402
from sast_agent.trace_engine import TraceEngine  # noqa: E402
from sast_agent.trace_schema import TraceStep, VerdictOut  # noqa: E402
from sast_agent.trace_schema import StepAssessment  # noqa: E402
from sast_agent.verifier import verify_finding  # noqa: E402

REPORTS_ROOT = config.REPO / "workspace" / "agent-reports"


def log(msg: str) -> None:
    print(f"[run_trace] {msg}", file=sys.stderr, flush=True)


def install_dry_run_stubs() -> None:
    """Zero-LLM smoke: every sink traces to an honest dead end and gets a
    stub not-vulnerable verdict; the queue->validate->score->render chain
    is exercised for real."""
    async def fake_step(prompt: str, budget: int):
        return TraceStep(assessment=StepAssessment.DEAD,
                         rationale="dry-run stub: no LLM"), 0

    async def fake_verdict(prompt: str, budget: int):
        return VerdictOut(is_vulnerable=False, confidence=0.1,
                          reasoning="dry-run stub: no LLM", evidence=[]), 0

    tracer._ask_step = fake_step
    tracer._ask_verdict = fake_verdict


async def run_target(target: str, limit: int, only_sink: str = "",
                     no_verify: bool = False,
                     out_root: Path | None = None) -> dict:
    briefs = pipeline.screen(target)
    if only_sink:
        briefs = [b for b in briefs if only_sink in b.sink.id]
    if limit:
        briefs = briefs[:limit]
    log(f"{target}: {len(briefs)} sinks to trace "
        f"({sum(1 for b in briefs if b.gap.value != 'OK')} with gaps)")

    engine = TraceEngine(target, config.cache_dir(target))
    tools = engine.tools  # verifier reuses the red-lined read/search tools
    tree_path = config.target_cfg(target)["tree_path"]

    out_dir = (out_root / target) if out_root \
        else REPORTS_ROOT / f"{target}-trace"
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.jsonl"

    total_tokens = 0
    with open(findings_path, "w") as fh:
        for i, brief in enumerate(briefs, 1):
            remaining = config.MAX_TOTAL_LLM_TOKENS - total_tokens
            try:
                finding = await asyncio.wait_for(
                    tracer.trace_sink(brief, engine,
                                      token_budget=max(remaining, 0)),
                    timeout=config.SINK_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                from sast_agent.contracts import Verdict
                finding = Finding(
                    sink=brief.sink,
                    chain=brief.chains[0] if brief.chains else None,
                    verdict=Verdict(is_vulnerable=False, confidence=0.1,
                                    reasoning="Investigation incomplete: "
                                              "sink timeout. Recorded as not "
                                              "vulnerable with minimal "
                                              "confidence."),
                    confidence_level="SUSPICIOUS", evidence=[],
                    exploit_sketch=None, sanitizer_notes=None,
                    stats={"tool_calls": 0, "tokens": 0, "requests": 0,
                           "seconds": float(config.SINK_TIMEOUT_SECONDS),
                           "timeout_hit": True, "status": "timeout",
                           "tool_log": [], "chains": [
                               c.model_dump() for c in (brief.chains or [])]})
            total_tokens += finding.stats.get("tokens", 0)
            verifier_note = ""
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
            log(f"  [{i}/{len(briefs)}] {brief.sink.id} gap={brief.gap.value} "
                f"trace={finding.stats.get('trace_status', '?')} -> "
                f"vuln={finding.verdict.is_vulnerable} "
                f"({finding.confidence_level}, "
                f"{finding.stats.get('tool_calls', 0)} llm calls, "
                f"{finding.stats.get('tokens', 0)} tokens, "
                f"{finding.stats.get('seconds', 0)}s, "
                f"{finding.stats.get('status', '?')})" + verifier_note)
    log(f"findings written to {findings_path} (total {total_tokens} tokens)")
    return {"out_dir": out_dir, "tokens": total_tokens}


def finalize_target(target: str, out_dir: Path) -> dict:
    """Post-run tail: mechanical validation layer (rewrites findings.jsonl),
    then ground-truth scoring + report.md rendering. Returns the score dict."""
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
    root = REPORTS_ROOT / (time.strftime("%Y-%m-%d") + "-trace")
    if (root / "summary.json").exists():
        root = REPORTS_ROOT / (time.strftime("%Y-%m-%d-%H%M%S") + "-trace")
    return root


def run_all(limit: int, only_sink: str, no_verify: bool) -> int:
    """Batch mode (parallelism 2, aggregate summary.json for the baseline
    gate)."""
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
    for name in names:
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
                    choices=list(config.TARGETS) + list(config.CANARIES)
                    + ["all"])
    ap.add_argument("--limit", type=int, default=0,
                    help="trace only the first N sinks (smoke test)")
    ap.add_argument("--only-sink", default="",
                    help="trace only sinks whose id contains this substring")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the adversarial review (attacker/defender)")
    ap.add_argument("--dry-run", action="store_true",
                    help="zero-LLM smoke: stub the LLM, exercise everything else")
    args = ap.parse_args()

    if args.dry_run:
        install_dry_run_stubs()
    elif not config.API_KEY:
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
