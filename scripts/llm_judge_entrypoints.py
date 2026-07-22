#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pydantic-ai-slim[openai]>=2.0.0",
#     "python-dotenv>=1.0.0",
#     "httpx[socks]>=0.27",
# ]
# ///
"""LLM judgment layer for category-B (NON-sink) vulnerability classes.

For every HTTP entrypoint (with the source of the handler plus everything
reachable from it, extracted forward through the call graph by
analysis/joern/extract_entrypoint_snippets.sc), ask an LLM (DeepSeek via
pydantic-ai, OpenAI-compatible endpoint) to judge ALL 7 category-B classes
semantically — idor, business-logic, race-condition, priv-esc,
mass-assignment, broken-access-control, auth-flaws — then score the
verdicts against the category-B entries of the target's ground_truth.json.

Category A (sink-based) is out of scope here; see
scripts/llm_judge_sink_chains.py for that path.

Usage:
    uv run scripts/llm_judge_entrypoints.py --snippets /tmp/ep_snippets_py.jsonl \
        --ground-truth targets/python-flask/ground_truth.json \
        -o /tmp/verdicts_b_py.jsonl

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
from typing import Literal

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

B_CLASSES = (
    "idor",
    "business-logic",
    "race-condition",
    "priv-esc",
    "mass-assignment",
    "broken-access-control",
    "auth-flaws",
)

SYSTEM_PROMPT = """\
You are a senior application-security engineer reviewing ONE HTTP endpoint
(handler source plus the source of every internal function it can reach,
entrypoint first). Judge it for the 7 NON-sink vulnerability classes ONLY:

- idor: an object is fetched by a user-controlled id with no ownership or
  authorization check that the object belongs to the caller.
- business-logic: the flow violates intended business invariants (e.g.
  transfer/withdraw allowing negative amounts, self-transfer abuse,
  unlimited coupon reuse).
- race-condition: check-then-act on shared state without locking or
  atomicity (TOCTOU).
- priv-esc: a regular user can invoke admin-only functionality or elevate
  their own role.
- mass-assignment: request body/fields are bound wholesale to a model,
  allowing updates to unintended fields (role, balance, is_admin, ...).
- broken-access-control: the endpoint is missing authentication or
  authorization gating entirely.
- auth-flaws: broken authentication LOGIC — e.g. predictable tokens,
  missing password verification, hardcoded weak secrets used to sign
  tokens. Missing rate limiting/lockout alone is NOT enough; user
  enumeration via different responses is borderline — judge carefully.

Return a verdict for ALL 7 classes (one finding per class), so the review
is deterministic.

Be strict: only report is_vulnerable=true when the code shown demonstrates
the flaw. The snippets may be incomplete (callers, middleware, or framework
gating may be missing); judge from the evidence available and reflect
uncertainty in `confidence`."""


class Finding(BaseModel):
    vuln_type: Literal[
        "idor", "business-logic", "race-condition", "priv-esc",
        "mass-assignment", "broken-access-control", "auth-flaws",
    ] = Field(description="exactly one of the 7 category-B classes")
    is_vulnerable: bool = Field(
        description="True only if the code shown demonstrates the flaw"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="0..1")
    reasoning: str = Field(description="1-3 sentences: why the endpoint is or is not vulnerable to this class")


class Findings(BaseModel):
    findings: list[Finding] = Field(
        description="exactly one finding per category-B class (7 total)"
    )


def simple_name(full_name: str) -> str:
    """CPG method fullName -> bare method name.

    'routes/users.py:<module>.search' -> 'search' (python),
    'com.foo.UserController.search:java.lang.String(...)' -> 'search' (java/csharp),
    'routes/users.js:<global>.<lambda>0' -> '<lambda>0' (js).
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


_GT_TAG = re.compile(r"^\s*(?://|#)\s*(?:VULN|SAFE):.*(?:\n|$)", re.MULTILINE)


def strip_gt_tags(code: str) -> str:
    """Remove ground-truth marker comments (`// VULN: id` / `# SAFE: id`)
    from snippet source before prompting — the LLM must judge the code,
    not the label. Some frontends (pysrc2cpg, csharpsrc2cpg) start the
    method slice at the comment/attribute line above the handler, so the
    marker would otherwise leak into the prompt verbatim."""
    return _GT_TAG.sub("", code)


def build_prompt(record: dict) -> str:
    ep = record["entrypoint"]
    parts = [
        f"HTTP endpoint under review: {ep.get('route', '?')}",
        f"Handler: {simple_name(ep.get('method', '?'))} "
        f"({ep.get('file', '?')}:{ep.get('line', '?')})",
        "",
        "Source of the handler and every internal function it can reach "
        "(entrypoint first):",
    ]
    for s in record.get("snippets", []):
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


def route_specificity(gt_route: str, ep: str) -> int | None:
    """Match a ground-truth route ('GET /users/search') against an entrypoint
    route label. The gt path carries the router/controller mount prefix, the
    label often does not — so compare the label's path fragments as a SUFFIX
    of the gt path, plus the HTTP method.

    Returns the number of matched label segments (higher = more specific)
    when the label matches, None otherwise. Specificity lets the scorer
    disambiguate wildcard-only labels ('GET /:id') that suffix-match
    several gt routes ('GET /users/:id' AND 'GET /users/me/:id')."""
    parts = gt_route.split(None, 1)
    if len(parts) != 2:
        return 1 if gt_route.upper() in ep.upper() else None
    method, path = parts[0].upper(), parts[1]
    m = _ep_method(ep)
    if m and m != method:
        return None
    gt_segs = _norm_segs(path)
    cand: list[str] = []
    # quoted fragments (java/csharp annotation style) ...
    for frag in re.findall(r'"([^"]*)"', ep):
        cand.extend(_norm_segs(frag))
    # ... or the raw path after the verb ("GET /users/<id>" style)
    if not cand:
        ep_parts = ep.split(None, 1)
        if len(ep_parts) == 2 and _ep_method(ep_parts[0]):
            cand = _norm_segs(ep_parts[1])
    if not cand:
        return None
    if len(cand) <= len(gt_segs) and gt_segs[-len(cand):] == cand:
        return len(cand)
    return None


def route_matches(gt_route: str, ep: str) -> bool:
    return route_specificity(gt_route, ep) is not None


def entrypoint_matches_entry(record: dict, entry: dict) -> int:
    """Does this entrypoint record correspond to the ground-truth entry?

    Primary: file + function (robust for python, where the route label is a
    raw annotation). Fallback: file + route — needed for js/ts, where route
    handlers are anonymous lambdas ('<lambda>N') that never match the gt
    function name.

    Returns a match STRENGTH (0 = no match): function matches outrank any
    route match; among route matches the suffix specificity counts, so the
    scorer can keep only the most specific record(s) per gt entry."""
    gt_ep = entry.get("entrypoint", {})
    ep = record.get("entrypoint", {})
    gt_file = gt_ep.get("file", "")
    file_ok = bool(gt_file) and ep.get("file", "").endswith(gt_file)
    gt_fn = gt_ep.get("function", "")
    if gt_fn and file_ok and simple_name(ep.get("method", "")) == gt_fn:
        return 1000
    gt_route = gt_ep.get("route", "")
    if gt_route and (file_ok or not gt_file):
        spec = route_specificity(gt_route, ep.get("route", ""))
        if spec is not None:
            return spec
    return 0


async def judge_all(records: list[dict], concurrency: int) -> list[dict]:
    agent = Agent(
        OpenAIChatModel(MODEL, provider=OpenAIProvider(base_url=BASE_URL, api_key=API_KEY)),
        # PromptedOutput: DeepSeek thinking mode rejects forced tool_choice,
        # so ask for JSON in the prompt instead of tool-based output
        output_type=PromptedOutput(Findings),
        instructions=SYSTEM_PROMPT,
        retries=2,
    )
    sem = asyncio.Semaphore(concurrency)

    async def judge_one(record: dict) -> dict:
        base = {"entrypoint": record["entrypoint"], "callees": record.get("callees", [])}
        async with sem:
            try:
                result = await agent.run(build_prompt(record))
                findings = [f.model_dump() for f in result.output.findings]
                return {**base, "status": "JUDGED", "findings": findings}
            except Exception as e:  # model/API failure: keep the record, mark unjudged
                return {**base, "status": "ERROR",
                        "error": f"{type(e).__name__}: {e}"}

    return list(await asyncio.gather(*(judge_one(r) for r in records)))


def score(verdicts: list[dict], ground_truth: list[dict]) -> dict:
    """Score category-B ground-truth entries only. Category A is out of
    scope for this script."""
    errors = [v for v in verdicts if v["status"] == "ERROR"]
    rows, tp, fn, fp, tn = [], 0, 0, 0, 0
    for entry in ground_truth:
        if entry.get("category") != "B":
            continue
        vt = entry.get("vuln_type", "")
        scored = [
            (s, v) for v in verdicts
            if v["status"] in ("JUDGED", "ERROR")
            and (s := entrypoint_matches_entry(v, entry)) > 0
        ]
        # keep only the most specific match(es): a wildcard-only label such
        # as 'GET /:id' suffix-matches both 'GET /users/:id' (vulnerable)
        # and 'GET /users/me/:id' (safe) — attributing it to both would turn
        # the vulnerable record into a false positive on the safe sample
        best = max((s for s, _ in scored), default=0)
        matches = [v for s, v in scored if s == best]
        vuln_hits = [
            m for m in matches
            if any(f.get("vuln_type") == vt and f.get("is_vulnerable")
                   for f in m.get("findings", []))
        ]
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
            "entrypoints_matched": len(matches),
            "max_confidence": max(
                (f.get("confidence", 0) for m in vuln_hits
                 for f in m.get("findings", [])
                 if f.get("vuln_type") == vt and f.get("is_vulnerable")),
                default=0,
            ),
        })
    vuln_rows = [r for r in rows if r["expected"] == "vulnerable"]
    return {
        "rows": rows,
        "n_errors": len(errors),
        "recall_B": _recall(vuln_rows),
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
    ap.add_argument("--snippets", required=False,
                    help="JSONL from extract_entrypoint_snippets.sc")
    ap.add_argument("--from-verdicts", default="",
                    help="skip the LLM and re-score an existing verdicts JSONL")
    ap.add_argument("--ground-truth", required=True, help="target's ground_truth.json")
    ap.add_argument("-o", "--output", default="-", help="verdicts JSONL (default: stdout suppressed; use file)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0,
                    help="judge only the first N entrypoints (smoke test)")
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
            records = records[: args.limit]

        sys.stderr.write(f"// judging {len(records)} entrypoints with {MODEL}\n")
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
    print(f"\nRecall category B (non-sink):      {report['recall_B']}")
    print(f"Safe-sample false positives (B):   {report['safe_fp'] or 'none'}")
    print(f"TP={report['tp']} FN={report['fn']} FP={report['fp']} TN={report['tn']} "
          f"LLM errors={report['n_errors']}")
    print("\n(note: category A is out of scope for this script — "
          "use scripts/llm_judge_sink_chains.py for sink-based classes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
