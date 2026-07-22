#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pydantic-ai-slim[openai]>=2.0.0",
#     "python-dotenv>=1.0.0",
#     "httpx[socks]>=0.27",
# ]
# ///
"""LLM vulnerability-judgment layer for the Semgrep + Joern pipeline.

For every Semgrep sink -> Joern entrypoint chain (with source snippets
extracted by analysis/joern/extract_chain_snippets.sc), ask an LLM
(DeepSeek via pydantic-ai, OpenAI-compatible endpoint) whether the chain
is a REAL, exploitable vulnerability, then score the verdicts against the
target's ground_truth.json (recall on category-A vulns, false positives
on the SAFE samples).

Usage:
    uv run scripts/llm_judge_sink_chains.py --snippets /tmp/snippets_py.jsonl \
        --ground-truth targets/python-flask/ground_truth.json \
        -o /tmp/verdicts_py.jsonl

Env (mirrors ~/Code/agent-demo):
    DEEPSEEK_API_KEY   required (also read from ./.env or ~/Code/agent-demo/.env)
    DEEPSEEK_MODEL     default: deepseek-chat
    DEEPSEEK_BASE_URL  default: https://api.deepseek.com
"""

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from pydantic_ai import Agent, PromptedOutput
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

load_dotenv()
if not os.environ.get("DEEPSEEK_API_KEY"):
    load_dotenv(Path.home() / "Code" / "agent-demo" / ".env")

MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
API_KEY = os.environ.get("DEEPSEEK_API_KEY")

SYSTEM_PROMPT = """\
You are a senior application-security engineer reviewing ONE suspected
vulnerability found by a static-analysis pipeline (Semgrep located the sink,
Joern traced the call chain from an HTTP entrypoint to that sink).

Decide whether this is a TRUE, exploitable vulnerability reachable by a
remote attacker through the entrypoint, or a false positive.

Reason carefully about:
- whether attacker-controlled input actually flows into the sink's dangerous
  argument (vs. a constant, hardcoded, or unrelated value);
- whether there is EFFECTIVE sanitization/validation on the path
  (parameterized queries, escaping, allow-lists, entity disabling, locks
  where relevant) — superficial or bypassable checks do NOT count;
- whether the code shown is on the path from the entrypoint to the sink.

The snippets may be incomplete (e.g. a field's write site can be missing);
judge from the evidence available and reflect uncertainty in `confidence`.
Be strict: only report is_vulnerable=true when an attacker can plausibly
reach the sink with dangerous input."""


class Verdict(BaseModel):
    is_vulnerable: bool = Field(
        description="True only if attacker-controlled input from the HTTP "
        "entrypoint can reach the sink without effective sanitization"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="0..1")
    reasoning: str = Field(description="2-4 sentences: the taint path and why it is or is not exploitable")


def simple_name(full_name: str) -> str:
    """CPG method fullName -> bare method name.

    'routes/users.py:<module>.search' -> 'search' (python),
    'com.foo.UserController.search:java.lang.String(...)' -> 'search' (java/csharp).
    """
    if ":<module>." in full_name:
        return full_name.rsplit(".", 1)[-1]
    base = full_name.split(":", 1)[0]  # strip :returntype(params)
    return base.rsplit(".", 1)[-1] or full_name


def load_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            # joern log lines share stdout with the JSONL payload
            if line.startswith("{"):
                rows.append(json.loads(line))
    return rows


def chain_snippets(record: dict, chain: dict) -> list[dict]:
    """Snippets for one chain, ordered entrypoint -> sink."""
    by_fn = {s["function"]: s for s in record.get("snippets", [])}
    ordered = [by_fn[fn] for fn in chain.get("calls", []) if fn in by_fn]
    in_method = record["sink"].get("in_method", "")
    if in_method in by_fn and all(s["function"] != in_method for s in ordered):
        ordered.append(by_fn[in_method])
    return ordered


_GT_TAG = re.compile(r"^\s*(?://|#)\s*(?:VULN|SAFE):.*(?:\n|$)", re.MULTILINE)


def strip_gt_tags(code: str) -> str:
    """Remove ground-truth marker comments (`// VULN: id` / `# SAFE: id`)
    from snippet source before prompting — the LLM must judge the code,
    not the label. Some frontends (pysrc2cpg, csharpsrc2cpg) start the
    method slice at the comment/attribute line above the handler, so the
    marker would otherwise leak into the prompt verbatim."""
    return _GT_TAG.sub("", code)


def build_prompt(record: dict, chain: dict, snips: list[dict]) -> str:
    sink = record["sink"]
    parts = [
        f"Suspected vulnerability class: {sink.get('vuln_type') or 'unknown'} "
        f"(semgrep rule: {sink.get('rule') or 'n/a'})",
        f"Sink call: `{sink['name']}` at {sink['file']}:{sink['line']}",
        f"HTTP entrypoint: {chain.get('entrypoint', '?')}",
        "Call chain: " + " -> ".join(simple_name(c) for c in chain.get("calls", [])),
        "",
        "Source of every function on the chain (entrypoint first):",
    ]
    for s in snips:
        parts.append(
            f"\n----- {s['file']}:{s['start_line']}-{s['end_line']} "
            f"({simple_name(s['function'])}) -----\n{strip_gt_tags(s['code'])}"
        )
    return "\n".join(parts)


_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH")
# annotation/label fragments -> HTTP method (checked before bare method names
# because e.g. 'HttpGet' also contains 'GET')
_ANNO_METHODS = (
    ("HTTPDELETE", "DELETE"), ("HTTPPATCH", "PATCH"), ("HTTPGET", "GET"),
    ("HTTPPOST", "POST"), ("HTTPPUT", "PUT"),
    ("DELETEMAPPING", "DELETE"), ("PATCHMAPPING", "PATCH"),
    ("GETMAPPING", "GET"), ("POSTMAPPING", "POST"), ("PUTMAPPING", "PUT"),
)


def _ep_method(ep: str) -> str:
    up = ep.upper()
    for anno, m in _ANNO_METHODS:
        if anno in up:
            return m
    for m in _HTTP_METHODS:
        if re.search(rf"\b{m}\b", up):
            return m
    return ""


def _norm_segs(path: str) -> list[str]:
    """'/users/:id' -> ['users', '*'] — path placeholders (:id, {id}, <int:id>)
    all normalize to '*'."""
    return [
        "*" if s.startswith((":", "{", "<")) else s
        for s in path.split("/") if s
    ]


def route_matches(gt_route: str, ep: str) -> bool:
    """Match a ground-truth route ('GET /users/search') against a chain
    entrypoint label, which per language looks like:
      js:  'GET \"/search\"' (router-relative path, quoted)
      java:'UserController @GetMapping(\"/search\")'
      cs:  'UsersController Route(\"users\") HttpGet(\"search\")'
    The gt path carries the router/controller mount prefix, the label often
    does not — so compare the quoted label fragments as a SUFFIX of the gt
    path, plus the HTTP method."""
    parts = gt_route.split(None, 1)
    if len(parts) != 2:
        return gt_route.upper() in ep.upper()
    method, path = parts[0].upper(), parts[1]
    m = _ep_method(ep)
    if m and m != method:
        return False
    gt_segs = _norm_segs(path)
    cand: list[str] = []
    for frag in re.findall(r'"([^"]*)"', ep):
        cand.extend(_norm_segs(frag))
    if not cand:
        return False
    return len(cand) <= len(gt_segs) and gt_segs[-len(cand):] == cand


def chain_matches_entry(record: dict, chain: dict, entry: dict) -> bool:
    """Does this sink+chain correspond to the ground-truth entry?"""
    if record["sink"].get("vuln_type") != entry.get("vuln_type"):
        return False
    gt_sink = entry.get("sink")
    ep = chain.get("entrypoint", "")
    calls = chain.get("calls", [])
    gt_route = entry.get("entrypoint", {}).get("route", "")
    route_ok = bool(gt_route) and route_matches(gt_route, ep)
    if gt_sink and not record["sink"]["file"].endswith(gt_sink["file"]):
        # Semgrep also flags calls that merely FORWARD to the real sink
        # (e.g. db.query in a route file forwarding to pool.query in db/).
        # Accept such a sink when it sits on the gt dataflow chain AND the
        # route matches — same logical vulnerability, coarser attribution.
        on_chain = any(record["sink"]["file"].endswith(f) for f in entry.get("chain", []))
        if not (on_chain and route_ok):
            return False
    gt_fn = entry.get("entrypoint", {}).get("function", "")
    if gt_fn and calls and simple_name(calls[0]) == gt_fn:
        return True
    if gt_fn and gt_fn == simple_name(ep):
        return True
    return route_ok


async def judge_all(records: list[dict], concurrency: int) -> list[dict]:
    agent = Agent(
        OpenAIChatModel(MODEL, provider=OpenAIProvider(base_url=BASE_URL, api_key=API_KEY)),
        # PromptedOutput: DeepSeek thinking mode rejects forced tool_choice,
        # so ask for JSON in the prompt instead of tool-based output
        output_type=PromptedOutput(Verdict),
        instructions=SYSTEM_PROMPT,
        retries=2,
    )
    sem = asyncio.Semaphore(concurrency)

    async def judge_one(record: dict, chain: dict) -> dict:
        snips = chain_snippets(record, chain)
        prompt = build_prompt(record, chain, snips)
        base = {
            "sink": record["sink"],
            "entrypoint": chain.get("entrypoint", ""),
            # raw CPG fullNames — simple_name() is applied only for display
            "calls": chain.get("calls", []),
        }
        async with sem:
            try:
                result = await agent.run(prompt)
                v = result.output
                return {**base, "status": "JUDGED", "is_vulnerable": v.is_vulnerable,
                        "confidence": v.confidence, "reasoning": v.reasoning}
            except Exception as e:  # model/API failure: keep the chain, mark unjudged
                return {**base, "status": "ERROR", "error": f"{type(e).__name__}: {e}"}

    tasks = []
    for record in records:
        chains = record.get("chains", [])
        if not chains:
            tasks.append(asyncio.ensure_future(asyncio.sleep(0, result={
                "sink": record["sink"], "entrypoint": "", "calls": [],
                "status": "NO_CHAIN",
            })))
        for chain in chains:
            tasks.append(asyncio.ensure_future(judge_one(record, chain)))
    return list(await asyncio.gather(*tasks))


def score(verdicts: list[dict], ground_truth: list[dict]) -> dict:
    errors = [v for v in verdicts if v["status"] == "ERROR"]
    rows, tp, fn, fp, tn = [], 0, 0, 0, 0
    for entry in ground_truth:
        vt = entry.get("vuln_type", "")
        matches = [
            v for v in verdicts
            if v["status"] in ("JUDGED", "ERROR")
            and chain_matches_entry({"sink": v["sink"]}, v, entry)
        ]
        vuln_hits = [m for m in matches if m.get("is_vulnerable")]
        expected = entry["expected"]
        if expected == "vulnerable":
            ok = bool(vuln_hits)
            tp += ok
            fn += not ok
            verdict = "TP" if ok else "FN"
        else:  # safe sample
            bad = bool(vuln_hits)
            fp += bad
            tn += not bad
            verdict = "FP" if bad else "TN"
        rows.append({
            "id": entry["id"], "category": entry["category"], "vuln_type": vt,
            "expected": expected, "verdict": verdict,
            "chains_matched": len(matches),
            "max_confidence": max((m.get("confidence", 0) for m in vuln_hits), default=0),
        })
    cat_a = [r for r in rows if r["category"] == "A" and r["expected"] == "vulnerable"]
    cat_b = [r for r in rows if r["category"] == "B" and r["expected"] == "vulnerable"]
    return {
        "rows": rows,
        "n_errors": len(errors),
        "recall_A": _recall(cat_a),
        "recall_B": _recall(cat_b),
        "recall_all_vuln": _recall([r for r in rows if r["expected"] == "vulnerable"]),
        "safe_fp": [r["id"] for r in rows if r["expected"] == "safe" and r["verdict"] == "FP"],
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


def _recall(rows: list[dict]) -> str:
    if not rows:
        return "n/a"
    hit = sum(1 for r in rows if r["verdict"] == "TP")
    return f"{hit}/{len(rows)} = {hit / len(rows):.0%}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--snippets", required=False, help="JSONL from extract_chain_snippets.sc")
    ap.add_argument("--from-verdicts", default="",
                    help="skip the LLM and re-score an existing verdicts JSONL")
    ap.add_argument("--ground-truth", required=True, help="target's ground_truth.json")
    ap.add_argument("-o", "--output", default="-", help="verdicts JSONL (default: stdout suppressed; use file)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="judge only the first N chains (smoke test)")
    args = ap.parse_args()

    with open(args.ground_truth) as f:
        ground_truth = json.load(f)

    if args.from_verdicts:
        verdicts = load_jsonl(args.from_verdicts)
        sys.stderr.write(f"// re-scoring {len(verdicts)} verdicts from {args.from_verdicts}\n")
    else:
        if not args.snippets:
            sys.exit("--snippets is required unless --from-verdicts is given")
        if not API_KEY:
            sys.exit("DEEPSEEK_API_KEY not set (env, ./.env, or ~/Code/agent-demo/.env)")

        records = load_jsonl(args.snippets)

        if args.limit:
            kept, n = [], 0
            for r in records:
                chains = r.get("chains", [])
                if n >= args.limit:
                    break
                r = dict(r, chains=chains[: max(0, args.limit - n)])
                n += len(r["chains"])
                kept.append(r)
            records = kept

        sys.stderr.write(f"// judging {sum(len(r.get('chains', [])) for r in records)} chains "
                         f"from {len(records)} sinks with {MODEL}\n")
        verdicts = asyncio.run(judge_all(records, args.concurrency))

        out = "\n".join(json.dumps(v, ensure_ascii=False) for v in verdicts) + "\n"
        if args.output != "-":
            with open(args.output, "w") as f:
                f.write(out)
            sys.stderr.write(f"// verdicts written to {args.output}\n")

    report = score(verdicts, ground_truth)

    print(f"\n{'id':<28} {'cat':<3} {'vuln_type':<17} {'expected':<10} verdict")
    for r in report["rows"]:
        print(f"{r['id']:<28} {r['category']:<3} {r['vuln_type']:<17} {r['expected']:<10} {r['verdict']}")
    print(f"\nRecall category A (sink-based):  {report['recall_A']}")
    print(f"Recall category B (non-sink):    {report['recall_B']}  (out of sink-pipeline scope)")
    print(f"Recall all vulnerable:           {report['recall_all_vuln']}")
    print(f"Safe-sample false positives:     {report['safe_fp'] or 'none'}")
    print(f"TP={report['tp']} FN={report['fn']} FP={report['fp']} TN={report['tn']} "
          f"LLM errors={report['n_errors']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
