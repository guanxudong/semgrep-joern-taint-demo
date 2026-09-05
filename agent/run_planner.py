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
"""Category-B planner CLI (AGENT_MVP_PLAN.md §7A, milestone M6).

Runs the planner agent over each target: it reads the repo-map route digest
and submits a hypothesis queue (routes that look like they are MISSING a
check) to workspace/agent-cache/<target>/hypotheses.jsonl.

Coverage check (default on): AFTER the agent run, compares the queue against
the category-B entries of ground_truth.json — every B entry's route must be
covered by at least one hypothesis. Ground truth is used only here, for
validation; it is never visible to the agent (red line §9.2). Exit code 1
when any B route is uncovered.

Usage:
    uv run --offline agent/run_planner.py --target python-flask
    uv run --offline agent/run_planner.py --target all
    uv run --offline agent/run_planner.py --target all --no-check
"""

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # for the sast_agent package

from sast_agent import config  # noqa: E402
from sast_agent.planner import run_planner  # noqa: E402
from sast_agent.tools import SastTools  # noqa: E402

_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "JSP")


def log(msg: str) -> None:
    print(f"[run_planner] {msg}", file=sys.stderr, flush=True)


def _norm_segs(path: str) -> list[str]:
    """'/users/:id' -> ['users', '*'] — placeholders (:id, {id}, <int:id>)
    all normalize to '*'. Same convention as llm_judge_entrypoints.py."""
    return [
        "*" if s.startswith((":", "{", "<")) else s
        for s in path.split("/") if s
    ]


def route_covered(gt_route: str, hyp_route: str) -> bool:
    """A hypothesis route covers a ground-truth route when the HTTP verb
    matches (if both carry one) and the hypothesis's normalized path
    segments equal or suffix-match the gt path's (mount prefixes differ)."""
    gt_parts = gt_route.split(None, 1)
    if len(gt_parts) != 2:  # extensionless gt route (e.g. a bare "/X.jsp")
        return gt_route.strip().upper() in hyp_route.strip().upper()
    gt_method, gt_path = gt_parts[0].upper(), gt_parts[1]
    # tolerate labels copied from the digest ("GET /x -> Handler:13")
    hyp_route = re.split(r"\s+->\s+", hyp_route, maxsplit=1)[0]
    hyp_parts = hyp_route.split(None, 1)
    if len(hyp_parts) == 2 and hyp_parts[0].upper() in _HTTP_METHODS:
        # JSP scriptlet pages serve any verb; the digest labels them "JSP"
        if hyp_parts[0].upper() not in ("JSP", "ANY") \
                and hyp_parts[0].upper() != gt_method:
            return False
        hyp_path = hyp_parts[1]
    else:
        hyp_path = hyp_route
    hyp_segs = _norm_segs(hyp_path)
    gt_segs = _norm_segs(gt_path)
    if not hyp_segs:
        return False
    return (len(hyp_segs) <= len(gt_segs)
            and gt_segs[-len(hyp_segs):] == hyp_segs)


def check_coverage(target: str, hypotheses: list[dict]) -> dict:
    """Compare the hypothesis queue against ground-truth category-B entries
    (validation only, post-run). Returns per-target coverage stats."""
    with open(config.target_cfg(target)["ground_truth"]) as f:
        ground_truth = json.load(f)
    b_entries = [e for e in ground_truth if e.get("category") == "B"]

    rows, uncovered, type_mismatch = [], [], []
    for entry in b_entries:
        gt_route = entry.get("entrypoint", {}).get("route", "")
        hits = [h for h in hypotheses
                if gt_route and route_covered(gt_route, h.get("route", ""))]
        type_hits = [h for h in hits
                     if h.get("vuln_type") == entry.get("vuln_type")]
        covered = bool(hits)
        if not covered:
            uncovered.append(entry["id"])
        elif not type_hits:
            type_mismatch.append(
                f"{entry['id']} ({entry['vuln_type']}; hypotheses say "
                + "/".join(sorted({h['vuln_type'] for h in hits})) + ")")
        rows.append({"id": entry["id"], "route": gt_route,
                     "covered": covered,
                     "type_match": bool(type_hits)})
    return {"total": len(b_entries),
            "covered": sum(1 for r in rows if r["covered"]),
            "uncovered": uncovered, "type_mismatch": type_mismatch,
            "rows": rows}


def print_checklist(checklist: dict | None) -> None:
    """M8: one-line-per-class summary of the taxonomy coverage checklist
    (audit trail; warning only — the GT coverage check drives the exit
    code)."""
    if checklist is None:
        print("  taxonomy checklist: MISSING (planner did not report coverage)")
        return
    tag = " [derived fallback]" if checklist.get("derived") else ""
    print(f"  taxonomy checklist:{tag}")
    for e in checklist.get("entries", []):
        print(f"    {e['vuln_type']}: {e['routes_examined']} examined, "
              f"{len(e.get('submitted', []))} submitted, "
              f"{len(e.get('excluded', []))} excluded")


async def one_target(target: str, check: bool) -> dict:
    tools = SastTools(target, config.cache_dir(target))
    result = await run_planner(target, tools)
    st = result["stats"]
    log(f"{target}: {len(result['hypotheses'])} hypotheses "
        f"({st['tokens']} tokens, {st['seconds']}s, {st['status']}) "
        f"-> {result['path']}")
    out = {"hypotheses": len(result["hypotheses"]), "stats": st}
    print(f"\n=== {target} ===")
    print_checklist(result.get("checklist"))
    if check:
        cov = check_coverage(target, result["hypotheses"])
        out["coverage"] = cov
        print(f"B-route coverage: {cov['covered']}/{cov['total']}")
        for u in cov["uncovered"]:
            print(f"  UNCOVERED: {u}")
        for m in cov["type_mismatch"]:
            print(f"  type-mismatch: {m}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True,
                    choices=list(config.TARGETS) + ["all"])
    ap.add_argument("--no-check", action="store_true",
                    help="skip the ground-truth coverage check")
    args = ap.parse_args()

    if not config.API_KEY:
        sys.exit("DEEPSEEK_API_KEY not set (env, ./.env, or ~/Code/agent-demo/.env)")

    names = list(config.TARGETS) if args.target == "all" else [args.target]
    results = {}
    for name in names:  # sequential: 5 light planner runs, no need for pools
        results[name] = asyncio.run(one_target(name, not args.no_check))

    if args.no_check:
        return 0
    total = sum(r["coverage"]["total"] for r in results.values())
    covered = sum(r["coverage"]["covered"] for r in results.values())
    print(f"\nTOTAL B-route coverage: {covered}/{total}")
    if covered < total:
        print("M6 gate: FAIL (uncovered category-B routes)")
        return 1
    print("M6 gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
