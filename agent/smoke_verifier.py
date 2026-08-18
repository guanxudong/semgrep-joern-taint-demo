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
"""M4 acceptance smoke (AGENT_MVP_PLAN.md §8-M4): the verifier's defender
must intercept a false positive before it reaches the CONFIRMED column.

For every SAFE category-A ground-truth entry that has a matching finding in
workspace/agent-reports/<target>/findings.jsonl (produced by a previous
run_agent.py run), the script:

1. forces the finding to VULNERABLE/CONFIRMED — simulating an investigator
   mistake on a safe sample;
2. runs the real attacker/defender rounds (verifier.verify_finding);
3. applies the mechanical merge (report.apply_verifier);
4. checks the FP did NOT survive as vulnerable+CONFIRMED — and reports
   whether the defender achieved a full veto (verdict flipped).

Ground truth is read here only because this is the test harness, never by
any agent tool (red line §9.2).

Usage:
    uv run --offline agent/smoke_verifier.py --target python-flask
    uv run --offline agent/smoke_verifier.py --target all
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # for the sast_agent package

from sast_agent import config  # noqa: E402
from sast_agent import report as report_mod  # noqa: E402
from sast_agent.contracts import Finding  # noqa: E402
from sast_agent.tools import SastTools  # noqa: E402
from sast_agent.verifier import verify_finding  # noqa: E402

REPORTS_ROOT = config.REPO / "workspace" / "agent-reports"


def log(msg: str) -> None:
    print(f"[smoke_verifier] {msg}", file=sys.stderr, flush=True)


def _matches(f: dict, entry: dict) -> tuple[bool, bool]:
    """(matched, primary) — does this finding correspond to the ground-truth
    entry? Uses the same chain matching as scoring. `primary` mirrors the
    scoring rule for safe samples: the finding's SUBMITTED chain must be
    the safe sample's chain. A finding whose verdict is about a different
    (genuinely vulnerable) chain to the same shared sink only matches
    non-primarily — forcing it vulnerable would test the verifier on the
    wrong chain, so the caller skips it."""
    verdicts = [v for v in report_mod._finding_as_verdicts(f)
                if report_mod.chain_matches_entry({"sink": v["sink"]}, v, entry)]
    return bool(verdicts), any(v.get("primary") for v in verdicts)


async def check_target(target: str) -> tuple[int, int, int]:
    """Returns (checked, passed, vetoed)."""
    findings_path = REPORTS_ROOT / target / "findings.jsonl"
    if not findings_path.is_file():
        log(f"{target}: no findings at {findings_path} — run run_agent.py first")
        return 0, 0, 0
    cfg = config.target_cfg(target)
    findings = report_mod.load_findings(str(findings_path))
    with open(cfg["ground_truth"]) as fh:
        ground_truth = json.load(fh)
    safe_a = [e for e in ground_truth
              if e.get("expected") == "safe" and e.get("category") == "A"]
    tools = SastTools(target, config.cache_dir(target))

    checked = passed = vetoed = 0
    for entry in safe_a:
        match, primary = None, False
        for f in findings:
            m, p = _matches(f, entry)
            if m and p:
                match, primary = f, True
                break
            if m and match is None:
                match = f
        if match is None:
            log(f"{target}: {entry['id']} — no finding on this safe sink, skipped")
            continue
        if not primary:
            log(f"{target}: {entry['id']} — skipped: the sink "
                f"({match['sink']['id']}) is shared with a genuinely "
                f"vulnerable chain, and the finding's verdict is about that "
                f"chain, not this safe sample (scoring's primary-chain rule "
                f"already keeps it out of the FP column)")
            continue
        checked += 1
        # simulate the investigator mistake: vulnerable at CONFIRMED level
        forced = json.loads(json.dumps(match))  # deep copy
        forced["verdict"]["is_vulnerable"] = True
        forced["verdict"]["confidence"] = 0.9
        forced["confidence_level"] = "CONFIRMED"
        finding = Finding.model_validate(forced)

        vres = await verify_finding(finding, tools, token_budget=200_000)
        merged = report_mod.apply_verifier(
            finding.model_dump(), vres, cfg["tree_path"])
        vf = merged["stats"]["verifier"]
        veto = bool(vf.get("veto"))
        vetoed += veto
        # acceptance: the FP must not survive in the CONFIRMED column
        ok = not (merged["verdict"]["is_vulnerable"]
                  and merged["confidence_level"] == "CONFIRMED")
        passed += ok
        att = (vf.get("attacker") or {})
        dfn = (vf.get("defender") or {})
        log(f"{target}: {entry['id']} ({match['sink']['id']}) "
            f"{'PASS' if ok else 'FAIL'}"
            f"{' +VETO' if veto else ''} "
            f"[attacker exploit={att.get('exploit_possible')}, "
            f"defender sanitizer={dfn.get('effective_sanitizer')} "
            f"kind={dfn.get('kind')}, "
            f"status={vf.get('status')}]")
        if not ok:
            log(f"  attacker: {(att.get('reasoning') or '')[:300]}")
            log(f"  defender: {(dfn.get('reasoning') or '')[:300]}")
    return checked, passed, vetoed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True,
                    choices=list(config.TARGETS) + ["all"])
    args = ap.parse_args()

    if not config.API_KEY:
        sys.exit("DEEPSEEK_API_KEY not set (env, ./.env, or ~/Code/agent-demo/.env)")

    targets = list(config.TARGETS) if args.target == "all" else [args.target]
    checked = passed = vetoed = 0
    for t in targets:
        c, p, v = asyncio.run(check_target(t))
        checked += c
        passed += p
        vetoed += v
    print(f"\nsafe-sample interception: {passed}/{checked} passed "
          f"({vetoed} full vetoes)")
    if checked == 0:
        print("nothing checked (no safe-A findings matched) — inconclusive")
        return 2
    return 0 if passed == checked else 1


if __name__ == "__main__":
    sys.exit(main())
