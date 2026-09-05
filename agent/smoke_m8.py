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
"""M8 no-LLM smoke: TaxonomyEntry contract, submit_hypotheses coverage
round-trip + derived fallback, checklist rendering, B-class gate cases."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sast_agent package

from sast_agent.contracts import B_VULN_TYPES, TaxonomyEntry  # noqa: E402
from sast_agent import report  # noqa: E402
from sast_agent.tools import SastTools  # noqa: E402
import run_baseline as rb  # noqa: E402

failures = []


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


# --- contract: accept / reject ---
e = TaxonomyEntry(vuln_type="idor", routes_examined=3,
                  submitted=["GET /users/<int:id>"],
                  excluded=[{"route": "GET /users", "reason": "no id param"}])
check("TaxonomyEntry accept", e.vuln_type == "idor")
try:
    TaxonomyEntry(vuln_type="sqli", routes_examined=1)
    check("TaxonomyEntry rejects non-B class", False)
except Exception:
    check("TaxonomyEntry rejects non-B class", True)
try:
    TaxonomyEntry(vuln_type="idor", routes_examined=-1)
    check("TaxonomyEntry rejects negative examined", False)
except Exception:
    check("TaxonomyEntry rejects negative examined", True)

# --- submit_hypotheses with coverage (full, partial, invalid) ---
tmp = Path(tempfile.mkdtemp())
tools = SastTools.__new__(SastTools)  # bypass __init__ (no joern needed)
tools.cache_dir = tmp

hyp = {"route": "GET /users/<int:id>", "entrypoint": "routes/users.py:get_user",
       "vuln_type": "idor", "trigger_features": "path id",
       "rationale": "no ownership check"}
full_cov = [{"vuln_type": t, "routes_examined": 4,
             "submitted": ["GET /users/<int:id>"] if t == "idor" else [],
             "excluded": []} for t in B_VULN_TYPES]
r = tools.submit_hypotheses([hyp], coverage=full_cov)
check("submit_hypotheses full coverage ok", r["ok"] and r["accepted"] == 1)
cl = json.loads((tmp / "taxonomy_checklist.json").read_text())
check("full checklist not derived", cl["derived"] is False)
check("full checklist 7 classes", len(cl["entries"]) == 7)

partial = [{"vuln_type": "idor", "routes_examined": 4,
            "submitted": ["GET /users/<int:id>"], "excluded": []}]
r = tools.submit_hypotheses([hyp], coverage=partial)
cl = json.loads((tmp / "taxonomy_checklist.json").read_text())
check("partial checklist derived", cl["derived"] is True)
check("partial checklist still 7 classes", len(cl["entries"]) == 7)
idor = next(x for x in cl["entries"] if x["vuln_type"] == "idor")
check("partial keeps planner entry", idor["routes_examined"] == 4)
bac = next(x for x in cl["entries"]
           if x["vuln_type"] == "broken-access-control")
check("auto-filled class routes_examined=0", bac["routes_examined"] == 0)

r = tools.submit_hypotheses([hyp], coverage=[{"vuln_type": "sqli",
                                              "routes_examined": 1}])
cl = json.loads((tmp / "taxonomy_checklist.json").read_text())
check("invalid coverage -> derived fallback", cl["derived"] is True
      and len(cl["entries"]) == 7)
idor = next(x for x in cl["entries"] if x["vuln_type"] == "idor")
check("fallback idor got submitted route from queue",
      idor["submitted"] == ["GET /users/<int:id>"])
check("no coverage arg -> no checklist overwrite",
      "checklist_written_to" not in tools.submit_hypotheses([hyp]))

# --- render section ---
md = report.render_markdown_b([], None, cl)
check("render audit section", "## Taxonomy coverage audit" in md
      and "| idor |" in md)
md2 = report.render_markdown_b([], None, None)
check("render without checklist", "Not available" in md2)
md3 = report.render_markdown_b([], None,
                               {"derived": True, "entries": cl["entries"]})
check("derived warning rendered", "auto-filled" in md3)

# --- B-class regression gate (fabricated summary_b.json) ---
baseline = json.loads((rb.BASELINE_DIR / "baseline.json").read_text())
py_b = baseline["python-flask"]["judge_b"]
b_hit = int(py_b["recall"].split("/")[0]) if py_b.get("recall") else 7


def fab(hit, fps, fname):
    p = tmp / fname
    p.write_text(json.dumps({"targets": {"python-flask": {
        "recall_B": f"{hit}/7", "recall_B_hit": hit, "recall_B_total": 7,
        "safe_fp_b": fps, "tp": hit, "fn": 7 - hit, "fp": len(fps),
        "tn": 0, "tokens": 0, "report": "x"}}}))
    return p


check("gate B PASS at baseline", rb.compare_with_baseline(
    fab(b_hit, ["py-safe-02"], "sb_pass.json")) == 0)
check("gate B FAIL on recall drop", rb.compare_with_baseline(
    fab(b_hit - 1, [], "sb_drop.json")) == 1)
check("gate B FAIL on new safe FP", rb.compare_with_baseline(
    fab(b_hit, ["py-safe-09"], "sb_fp.json")) == 1)
# A-class summary still gates as before (fabricated, 1 target)
a_hit = int(baseline["python-flask"]["judge_a"]["recall"].split("/")[0])
pa = tmp / "sa_pass.json"
pa.write_text(json.dumps({"targets": {"python-flask": {
    "recall_A": f"{a_hit}/10", "recall_A_hit": a_hit, "safe_fp": []}}}))
check("gate A still PASS", rb.compare_with_baseline(pa) == 0)

print("\n" + ("ALL PASS" if not failures else f"FAILURES: {failures}"))
sys.exit(1 if failures else 0)
