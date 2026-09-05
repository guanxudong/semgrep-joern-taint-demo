"""Category-B planner agent (AGENT_MVP_PLAN.md §7A, milestone M6).

One pydantic-ai Agent run per target reads the repo-map digest (route table
+ symbol summaries) and produces the hypothesis queue: every route that
looks like it might be MISSING a check (the category-B evidence shape is
"absence", not "presence of a sink"). Hypotheses are enqueued via the
submit_hypotheses tool and land in workspace/agent-cache/<target>/
hypotheses.jsonl — the M7 workers will consume that queue.

Recall is the planner's job; precision is the M7 worker's. Ground truth is
never visible to the agent (red line §9.2) — run_planner.py checks coverage
against it only after the run.

Usage:
    from sast_agent.planner import run_planner
    result = await run_planner("python-flask", SastTools("python-flask"))
"""

import asyncio
import json
import time
from pathlib import Path

from pydantic_ai import Agent, RunContext, UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from . import config
from .contracts import B_VULN_TYPES, Hypothesis, TaxonomyEntry
from .tools import SastTools

_DIGEST_MAX_CHARS = 8000

_PLANNER_PROMPT = """\
You are a senior application-security engineer triaging a web application
for NON-sink vulnerability classes — flaws where the evidence is an ABSENT
check, not a dangerous function call. The 7 classes:

- idor: object fetched by user-supplied id with no ownership check
- broken-access-control: route reachable without the role/permission check
  its siblings have
- mass-assignment: request body bound wholesale to a model (no field
  allow-list)
- race-condition: read-then-write of balance/stock/state without a lock or
  atomic operation
- priv-esc: role/privilege derived from attacker-influenceable input
- business-logic: amount/quantity/state-transition invariants not enforced
- auth-flaws: login/token/password-reset weaknesses (no rate limit, weak
  token, predictable reset)

You are given a route table with per-route handler signatures and sibling
symbols. These trait -> class mappings are MANDATORY: when a route matches
the trait, the hypothesis MUST be submitted — you may record mitigating
evidence in the rationale, but you may NOT drop the hypothesis:

- path carries an :id / <id> / {{id}} parameter, or the handler fetches an
  object by request-supplied id -> ALWAYS submit idor (and
  broken-access-control when the route also looks role-restricted)
- POST/PUT binding a whole request body to a model -> ALWAYS submit
  mass-assignment
- read-then-write of balance/stock/inventory (withdraw, transfer,
  purchase) -> ALWAYS submit race-condition
- login / token / reset-password routes -> ALWAYS submit auth-flaws
- role or admin flag taken from request data -> ALWAYS submit priv-esc
- money / quantity / status transitions (transfer, coupon, refund) ->
  ALWAYS submit business-logic

This includes routes whose code visibly contains a guard (a lock, an
ownership check, an allow-list): submit them anyway and name the guard in
the rationale. Judging whether a guard is EFFECTIVE is the next stage's
job — a present-but-weak check is still a valid hypothesis, and a dropped
hypothesis is a guaranteed miss.

Your job:
1. Walk EVERY route in the digest below. For each, decide whether it
   matches one or more heuristics.
2. When the digest is not enough to judge (e.g. whether a decorator is an
   auth check, whether a POST body is bound wholesale), verify with
   search_code / read_function on the actual file before deciding.
3. A guard may be mounted globally (middleware, app init) instead of per
   route — if every route lacks a check, search for the shared idiom
   before blaming individual routes.
4. Submit ALL surviving hypotheses in ONE submit_hypotheses call. Each
   hypothesis needs: route (copy the digest's route label verbatim),
   entrypoint ("file:function"), vuln_type (one of the 7 classes),
   trigger_features (the route traits that matched), rationale (why the
   check looks absent, citing what you saw).
5. The SAME submit_hypotheses call must also carry the `coverage` argument:
   the taxonomy coverage checklist — for EACH of the 7 classes (all seven,
   even when nothing was submitted) report:
   - routes_examined: how many routes in the digest you actually looked at
     for that class;
   - submitted: the routes that produced a hypothesis for that class;
   - excluded: every route you CONSIDERED for that class but did not
     submit, each with a one-line reason (guard seen and looks effective,
     trait absent, not applicable, ...).
   This checklist is the audit trail proving no route was silently skipped —
   an omitted class or an unexplained exclusion is a recall hole.

Rules:
- Recall first: when in doubt, submit the hypothesis. A later stage
  re-verifies each one; your job is to not miss a suspicious route.
- One route MAY yield several hypotheses (different classes).
- The `route` field is just verb + path ("GET /users/{{id}}"); the handler
  goes in `entrypoint` as "file:function" — do not copy "-> name:line"
  into the route.
- Do NOT hypothesize about routes not in the digest; do NOT invent files,
  functions or decorators you have not seen in the digest or tool results.
- Only the 7 classes above. Dangerous-function-call flaws (SQL injection,
  XSS, command injection, ...) are covered by another pipeline — skip them.
- Budget: at most {max_calls} tool calls total."""


def _build_digest(target: str, tools: SastTools) -> str:
    """Compact route-table + symbol digest from the cached repo_map.json."""
    tools.get_repo_map()  # ensures the cache files exist
    data = json.loads((tools.cache_dir / "repo_map.json").read_text())

    lines = [f"ROUTE DIGEST for target {target}", ""]
    other_files: list[str] = []
    for f in data.get("files", []):
        path, role = f.get("path", "?"), f.get("role", "other")
        routes = f.get("routes") or []
        symbols = f.get("symbols") or []
        # transpiled JSP pages carry no route annotations; the D9 convention
        # is pages/X_jsp.java -> /X.jsp served by _jspService
        if not routes and path.startswith("pages/") and path.endswith("_jsp.java"):
            page = path[len("pages/"):-len("_jsp.java")]
            routes = [{"method": "JSP", "path": f"/{page}.jsp",
                       "function": "_jspService", "line": 0}]
        if not routes:
            sigs = ", ".join(s.get("name", "?") for s in symbols[:6])
            other_files.append(f"{path} ({role}): {sigs}")
            continue
        lines.append(f"{path} (role={role})")
        for r in routes:
            lines.append(f"  {r.get('method', '?')} {r.get('path', '?')} "
                         f"-> {r.get('function', '?')}:{r.get('line', 0)}")
        for s in symbols[:10]:
            lines.append(f"    symbol: {s.get('signature') or s.get('name', '?')}")
        lines.append("")
    if other_files:
        lines.append("OTHER FILES (no routes):")
        lines.extend("  " + o for o in other_files[:25])

    text = "\n".join(lines)
    if len(text) > _DIGEST_MAX_CHARS:
        text = text[:_DIGEST_MAX_CHARS] + "\n... [truncated]"
    return text


def build_planner_agent() -> Agent:
    agent = Agent(
        OpenAIChatModel(config.MODEL, provider=OpenAIProvider(
            base_url=config.BASE_URL, api_key=config.API_KEY)),
        deps_type=SastTools,
        instructions=_PLANNER_PROMPT.format(
            max_calls=config.PLANNER_MAX_TOOL_CALLS),
        retries=2,
    )

    @agent.tool
    def search_code(ctx: RunContext[SastTools], pattern: str,
                    glob: str | None = None) -> str:
        """Regex search across the target tree (ripgrep, ±2 lines of
        context). Use it to check decorators, bindings and shared guards."""
        return ctx.deps.search_code(pattern, glob)

    @agent.tool
    def read_function(ctx: RunContext[SastTools], file: str,
                      start: int, end: int) -> str:
        """Read lines start..end (1-based, inclusive) of a source file in
        the target tree, with line numbers."""
        return ctx.deps.read_function(file, start, end)

    @agent.tool
    def submit_hypotheses(ctx: RunContext[SastTools],
                          hypotheses: list[Hypothesis],
                          coverage: list[TaxonomyEntry]) -> dict:
        """Submit the hypothesis queue AND the taxonomy coverage checklist.
        Call exactly once, last. `coverage` must have one entry per each of
        the 7 classes: routes_examined, submitted routes, and excluded
        routes with reasons."""
        return ctx.deps.submit_hypotheses(
            [h.model_dump() for h in hypotheses],
            coverage=[e.model_dump() for e in coverage])

    return agent


async def run_planner(target: str, tools: SastTools) -> dict:
    """One planner run over a target. Truncates hypotheses.jsonl first, then
    returns {"hypotheses": [...], "stats": {...}, "checklist": {...}|None}."""
    out = tools.cache_dir / "hypotheses.jsonl"
    out.write_text("")  # fresh queue per run
    cov_path = tools.cache_dir / "taxonomy_checklist.json"
    cov_path.unlink(missing_ok=True)  # stale checklists must not survive

    digest = _build_digest(target, tools)
    stats = {"tokens": 0, "requests": 0, "seconds": 0.0,
             "status": "submitted", "digest_chars": len(digest)}
    start = time.monotonic()
    agent = build_planner_agent()
    try:
        result = await asyncio.wait_for(
            agent.run(
                "Here is the route digest. Produce the hypothesis queue.\n\n"
                + digest,
                deps=tools,
                usage_limits=UsageLimits(
                    request_limit=config.PLANNER_MAX_TOOL_CALLS),
            ),
            timeout=config.PLANNER_TIMEOUT_SECONDS,
        )
        usage = result.usage
        stats["requests"] = usage.requests
        stats["tokens"] = usage.total_tokens or (
            (usage.input_tokens or 0) + (usage.output_tokens or 0))
    except UsageLimitExceeded:
        stats["status"] = "budget_exhausted"
    except asyncio.TimeoutError:
        stats["status"] = "timeout"
    except Exception as e:
        stats["status"] = f"error: {type(e).__name__}: {e}"
    stats["seconds"] = round(time.monotonic() - start, 1)

    hypotheses = []
    for line in out.read_text().splitlines():
        line = line.strip()
        if line:
            hypotheses.append(Hypothesis.model_validate_json(line)
                              .model_dump())
    if not hypotheses and stats["status"] == "submitted":
        stats["status"] = "no_submission"
    checklist = None
    if cov_path.exists():
        checklist = json.loads(cov_path.read_text())
    return {"hypotheses": hypotheses, "stats": stats, "checklist": checklist,
            "path": str(Path(out).relative_to(config.REPO))}
