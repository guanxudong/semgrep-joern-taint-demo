#!/usr/bin/env python3
"""Chain-level confirmation report (D3): join backward call chains with
dataflow confirmation flows, emitting CONFIRMED/UNCONFIRMED per
entrypoint -> sink chain (instead of per sink).

Inputs:
  --chains  JSONL written by backward_from_sinks.sc (CHAINS_JSON=...):
            {"sink": {...}, "chains": [{"route", "entrypoint", "path": [...]}]}
  --taint   JSONL written by taint_confirm.sc:
            {"sink": {...}, "status", "flows": [{"source_method", "path"}]}

A chain is CONFIRMED when the matching taint record has at least one flow
whose source_method attributes to the chain's entrypoint (method fullName;
for JS lambdas the "<lambda>N [GET /route]" form is matched on either part).

Usage:
    python3 scripts/chain_report.py --chains /tmp/chains_py.jsonl \
        --taint /tmp/taint_py.jsonl -o /tmp/report_py.jsonl
"""

import argparse
import json
import sys


def load_jsonl(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            # joern log lines ([INFO ] ...) share stdout with the JSONL payload
            if line.startswith("{"):
                rows.append(json.loads(line))
    return rows


def sink_key(sink):
    return (sink.get("file", ""), sink.get("line", -1))


def flow_matches_chain(source_method, chain):
    ep = chain.get("entrypoint", "")
    if source_method == ep or source_method == chain.get("route"):
        return True
    # JS: a flow may start in a lambda NESTED inside the route handler
    # ("<lambda>2:<lambda>3 [...]") — match on the entrypoint prefix.
    if ep and source_method.startswith(ep + ":"):
        return True
    # JS: "<lambda>N [GET /users/search]" -> match on lambda name or route
    if " [" in source_method and source_method.endswith("]"):
        lam, route = source_method.rsplit(" [", 1)
        return lam == ep or route[:-1] == chain.get("route")
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--chains", required=True, help="CHAINS_JSON output of backward_from_sinks.sc")
    ap.add_argument("--taint", required=True, help="JSONL output of taint_confirm.sc")
    ap.add_argument("-o", "--output", default="-", help="output file (default: stdout)")
    args = ap.parse_args()

    chains_rows = load_jsonl(args.chains)
    taint_rows = load_jsonl(args.taint)

    taint_by_key = {}
    for row in taint_rows:
        taint_by_key.setdefault(sink_key(row.get("sink", {})), []).append(row)

    report = []
    matched_taint = set()
    for row in chains_rows:
        sink = row.get("sink", {})
        key = sink_key(sink)
        taints = taint_by_key.get(key, [])
        if not taints:
            sys.stderr.write(f"// warn: no taint record for sink {key[0]}:{key[1]}\n")
        matched_taint.add(key)
        flows = [fl for t in taints for fl in t.get("flows", [])]
        chains = row.get("chains", [])
        if not chains:
            # sink matched in the CPG but no call chain to any entrypoint
            # (e.g. csharpsrc2cpg dropping CALL edges into Services/)
            report.append(
                {
                    "route": "",
                    "entrypoint": "",
                    "sink": sink,
                    "status": "NO_CHAIN",
                    "flows": len(flows),
                }
            )
        for chain in chains:
            hits = [fl for fl in flows if flow_matches_chain(fl.get("source_method", ""), chain)]
            report.append(
                {
                    "route": chain.get("route", ""),
                    "entrypoint": chain.get("entrypoint", ""),
                    "sink": sink,
                    "status": "CONFIRMED" if hits else "UNCONFIRMED",
                    "flows": len(hits),
                }
            )

    # taint sinks that no backward chain reached (or that have no chains at all)
    for row in taint_rows:
        sink = row.get("sink", {})
        key = sink_key(sink)
        if key not in matched_taint:
            report.append(
                {
                    "route": "",
                    "entrypoint": "",
                    "sink": sink,
                    "status": "NO_CHAIN",
                    "flows": len(row.get("flows", [])),
                }
            )

    out = "\n".join(json.dumps(r) for r in report) + ("\n" if report else "")
    if args.output == "-":
        sys.stdout.write(out)
    else:
        with open(args.output, "w") as f:
            f.write(out)

    confirmed = sum(1 for r in report if r["status"] == "CONFIRMED")
    unconfirmed = sum(1 for r in report if r["status"] == "UNCONFIRMED")
    no_chain = sum(1 for r in report if r["status"] == "NO_CHAIN")
    sys.stderr.write(
        f"// chains: {len(report)} total, {confirmed} CONFIRMED, "
        f"{unconfirmed} UNCONFIRMED, {no_chain} NO_CHAIN\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
