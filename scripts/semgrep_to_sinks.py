#!/usr/bin/env python3
"""Convert Semgrep JSON output into a compact sink list for the Joern scripts.

Usage:
    semgrep --config analysis/rules/sinks-python.yml --json -o raw.json targets/python-flask
    python3 scripts/semgrep_to_sinks.py raw.json --root targets/python-flask -o sinks_py.json

The output is a JSON array of:
    {"file": "routes/users.py", "line": 14, "rule": "py-sink-sqli",
     "vuln_type": "sqli", "cwe": "89"}

`file` is made relative to --root so it matches the paths stored inside the
CPG (Joern stores paths relative to the directory given to joern-parse).
"""

import argparse
import json
import os
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("semgrep_json", help="Semgrep --json output file")
    ap.add_argument("--root", default="", help="strip this prefix from result paths")
    ap.add_argument("-o", "--output", default="-", help="output file (default: stdout)")
    args = ap.parse_args()

    with open(args.semgrep_json) as f:
        data = json.load(f)

    root = args.root.rstrip("/")
    sinks = []
    for r in data.get("results", []):
        path = r.get("path", "")
        if root and path.startswith(root + "/"):
            path = path[len(root) + 1:]
        meta = r.get("extra", {}).get("metadata", {})
        sinks.append(
            {
                "file": path,
                "line": r.get("start", {}).get("line", -1),
                "rule": r.get("check_id", "").split(".")[-1],
                "vuln_type": meta.get("vuln_type", ""),
                "cwe": str(meta.get("cwe", "")),
            }
        )

    out = json.dumps(sinks, indent=2)
    if args.output == "-":
        print(out)
    else:
        with open(args.output, "w") as f:
            f.write(out + "\n")
        print(f"wrote {len(sinks)} sinks to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
