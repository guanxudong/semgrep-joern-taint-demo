#!/usr/bin/env python3
"""Compare repo maps (tree-sitter vs joern) against a target's ground_truth.json.

For each map JSON (schema shared by scripts/repo_map.py and
analysis/joern/repo_map.sc), reports route-hit and function-hit rates against
the ground truth's entrypoint.route / entrypoint.function fields, plus basic
coverage stats (files, symbols, routes, references).

Usage:
    python3 scripts/compare_repo_maps.py --ground-truth targets/python-flask/ground_truth.json \
        /tmp/repo_map_a_py.json /tmp/repo_map_b_py.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def norm_route(method: str, path: str) -> tuple[str, str]:
    p = re.sub(r"<[^>]+>", "{}", path)   # flask <int:id>
    p = re.sub(r":[^/]+", "{}", p)       # express :id
    p = re.sub(r"\{[^}]+\}", "{}", p)    # spring/aspnet {id}
    p = re.sub(r"/+", "/", p).rstrip("/") or "/"
    return method.upper(), p


def score(map_path: str, gt: list[dict]) -> dict:
    data = json.loads(Path(map_path).read_text())
    extracted = []
    n_symbols = 0
    for f in data["files"]:
        n_symbols += len(f.get("symbols", []))
        for r in f.get("routes", []):
            extracted.append((f["path"], r))
    route_hit = func_hit = total = 0
    misses = []
    for entry in gt:
        ep = entry.get("entrypoint") or {}
        route = ep.get("route")
        if not route:
            continue
        total += 1
        method, _, path = route.partition(" ")
        want = norm_route(method, path)
        match = next(((fp, r) for fp, r in extracted
                      if norm_route(r["method"], r["path"]) == want), None)
        if not match:
            misses.append(f"ROUTE MISS  {entry['id']}: {route} ({ep.get('file')})")
            continue
        route_hit += 1
        fp, r = match
        if ep.get("function") == r["function"]:
            func_hit += 1
        else:
            misses.append(
                f"FUNC MISS   {entry['id']}: {route} want `{ep.get('function')}`"
                f" got `{r['function']}` ({fp})")
    return {
        "tool": data.get("tool", "?"),
        "map": map_path,
        "files": len(data["files"]),
        "symbols": n_symbols,
        "routes": len(extracted),
        "references": len(data.get("references", [])),
        "route_hit": route_hit,
        "func_hit": func_hit,
        "total": total,
        "misses": misses,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("maps", nargs="+", help="repo map JSON files")
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--verbose", action="store_true", help="print per-entry misses")
    args = ap.parse_args()

    gt = json.loads(Path(args.ground_truth).read_text())
    rows = [score(m, gt) for m in args.maps]

    print(f"ground truth: {args.ground_truth}")
    hdr = f"{'tool':<12} {'files':>5} {'symbols':>7} {'routes':>6} {'refs':>5} {'route hits':>12} {'func hits':>11}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['tool']:<12} {r['files']:>5} {r['symbols']:>7} {r['routes']:>6} "
              f"{r['references']:>5} {r['route_hit']:>5}/{r['total']:<6} "
              f"{r['func_hit']:>4}/{r['total']:<6}")
    if args.verbose:
        for r in rows:
            if r["misses"]:
                print(f"\n[{r['tool']}] misses ({r['map']}):")
                for m in r["misses"]:
                    print("  " + m)


if __name__ == "__main__":
    main()
