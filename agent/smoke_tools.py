#!/usr/bin/env python3
"""M1 smoke test: exercise every sast_agent tool on targets/python-flask and
assert the facts match the frozen baseline (workspace/baseline/python-flask/).

Usage:
    python3 agent/smoke_tools.py

Prints PASS/FAIL per assertion and exits non-zero on any failure. The script
itself is stdlib-only; if the ambient python3 lacks pydantic it re-execs
itself under `uv run --with pydantic --with python-dotenv`.
"""

import os
import sys
from pathlib import Path

# sast_agent needs pydantic; re-exec under uv if the ambient python3 lacks it.
try:
    import pydantic  # noqa: F401
except ImportError:
    if os.environ.get("SAST_SMOKE_UV"):
        raise
    os.environ["SAST_SMOKE_UV"] = "1"
    # bare "python3" (not sys.executable) resolves to the uv venv interpreter
    os.execvp("uv", ["uv", "run", "--no-project",
                     "--with", "pydantic", "--with", "python-dotenv",
                     "python3", os.path.abspath(__file__)])

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sast_agent import config, pipeline  # noqa: E402
from sast_agent.tools import SastTools  # noqa: E402

TARGET = "python-flask"
# the get_user query sink (workspace/baseline/python-flask/chains.jsonl line 1)
QUERY_SINK_ID = "data/db.py:16:py-sink-sqli"

_failures = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _failures
    if not ok:
        _failures += 1
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f"  [{detail}]" if detail else ""))


def main() -> int:
    # 1. CPG builds in the agent cache
    cpg = pipeline.ensure_cpg(TARGET)
    check("ensure_cpg builds cpg.bin", cpg.is_file(), str(cpg))

    # 2. semgrep finds >= 12 sinks (baseline: 13)
    sinks = pipeline.run_semgrep(TARGET)
    check("run_semgrep returns >= 12 sinks", len(sinks) >= 12, f"got {len(sinks)}")

    # 3. chains for the db.py:16 sqli sink are non-empty
    chains = pipeline.get_chains(TARGET)
    sink_chains = chains.get(QUERY_SINK_ID, [])
    check("get_chains: db.py:16 sink has non-empty chains", len(sink_chains) > 0,
          f"{len(sink_chains)} chains")
    check("get_chains: a chain starts at the get_user entrypoint",
          any("get_user" in c.entrypoint for c in sink_chains))

    # 4. taint for the same sink is CONFIRMED with a get_user-sourced flow
    taints = pipeline.get_taint_flows(TARGET)
    tf = taints.get(QUERY_SINK_ID)
    check("get_taint_flows: db.py:16 sink confirmed", bool(tf and tf.confirmed))
    check("get_taint_flows: a flow's source mentions get_user",
          bool(tf and any("get_user" in f for f in tf.flows)))

    tools = SastTools(TARGET, config.cache_dir(TARGET))

    # 5. read_function returns real source
    src = tools.read_function("data/db.py", 1, 40)
    check("read_function returns source containing 'def query'", "def query" in src)

    # 6. ground-truth isolation (red line §9.2)
    refused = tools.read_function("../ground_truth.json", 1, 5)
    check("read_function refuses ../ground_truth.json", refused.startswith("ERROR"))
    hits = tools.search_code("expected")
    check("search_code never returns ground_truth hits",
          "ground_truth" not in hits and "GROUND_TRUTH" not in hits)

    # 7. joern_query callers_of runs and returns rows
    rows = tools.joern_query("callers_of", "query")
    check("joern_query callers_of('query') returns rows",
          isinstance(rows, list) and len(rows) > 0,
          f"{len(rows)} rows" if isinstance(rows, list) else str(rows)[:120])

    # 8. joern_query methods_in_file runs and returns rows
    rows = tools.joern_query("methods_in_file", "db.py")
    check("joern_query methods_in_file('db.py') returns rows",
          isinstance(rows, list) and len(rows) > 0,
          f"{len(rows)} rows" if isinstance(rows, list) else str(rows)[:120])

    # 9. submit_hypotheses: valid entry accepted, bad vuln_type rejected
    ok_res = tools.submit_hypotheses([{
        "route": "GET /users/<id>", "entrypoint": "routes/users.py:get_user",
        "vuln_type": "idor", "trigger_features": "path <id>, no auth decorator",
        "rationale": "smoke: no ownership check visible",
    }])
    check("submit_hypotheses accepts a valid hypothesis",
          ok_res.get("ok") and ok_res.get("accepted") == 1, str(ok_res)[:120])
    bad_res = tools.submit_hypotheses([{
        "route": "GET /x", "entrypoint": "a.py:b", "vuln_type": "sqli",
        "trigger_features": "x", "rationale": "y",
    }])
    check("submit_hypotheses rejects a non-B vuln_type",
          not bad_res.get("ok") and bad_res.get("accepted") == 0
          and len(bad_res.get("rejected", [])) == 1, str(bad_res)[:120])

    # 10. get_forward_slice returns the handler + callees, GT tags stripped
    slice_ = tools.get_forward_slice("get_user")
    check("get_forward_slice('get_user') returns snippets",
          isinstance(slice_, dict) and len(slice_.get("snippets", [])) > 0,
          f"{len(slice_.get('snippets', []))} snippets"
          if isinstance(slice_, dict) else str(slice_)[:120])
    if isinstance(slice_, dict):
        blob = "\n".join(s.get("code", "") for s in slice_.get("snippets", []))
        check("get_forward_slice strips VULN:/SAFE: markers",
              "VULN:" not in blob and "SAFE:" not in blob)
    miss = tools.get_forward_slice("no_such_function_xyz")
    check("get_forward_slice reports unknown entrypoints",
          isinstance(miss, str) and miss.startswith("ERROR"))

    print(f"\n{'ALL PASS' if _failures == 0 else f'{_failures} FAILURES'}")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
