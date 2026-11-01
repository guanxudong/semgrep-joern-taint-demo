"""No-LLM tests for the tracer state machine (A-class v2).

Covers: trace_schema validation, the tracer loop driven by a scripted fake
LLM + fake engine (complete / dead / budget / no-progress / bad-selection
paths), the report.py llm_inferred-hop validation rule, and candidate
shaping. Run: uv run --with pytest pytest tests/test_trace.py -q
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

# sast_agent.config load_dotenv()s the repo .env at import time, which would
# leak DEEPSEEK_* into os.environ for the whole pytest process and break
# test_gate's provenance assertions (run_baseline reads the env at call
# time). Snapshot and restore around the import.
_SAVED_ENV = {k: os.environ.get(k)
              for k in ("DEEPSEEK_MODEL", "DEEPSEEK_BASE_URL",
                        "DEEPSEEK_API_KEY")}

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))

from sast_agent import config, report, tracer  # noqa: E402

for _k, _v in _SAVED_ENV.items():
    if _v is None:
        os.environ.pop(_k, None)
    else:
        os.environ[_k] = _v
del _SAVED_ENV, _k, _v
from sast_agent.contracts import (Chain, Gap, InvestigationBrief, Sink,  # noqa: E402
                                  TaintFlow)
from sast_agent.trace_engine import rows_to_candidates  # noqa: E402
from sast_agent.trace_schema import (Hop, HopSelection, TraceDirective,  # noqa: E402
                                     TraceStep, VerdictOut, StepAssessment,
                                     Edge)


# ---------------------------------------------------------------------------
# schema validation
# ---------------------------------------------------------------------------

def test_directive_kind_enum():
    TraceDirective(kind="callers_of", symbol="foo")
    with pytest.raises(Exception):
        TraceDirective(kind="DROP TABLE", symbol="foo")


def test_llm_hop_requires_justify_ref():
    Hop(method="m", edge=Edge.ENGINE)  # engine hops need none
    with pytest.raises(Exception):
        Hop(method="m", edge="llm_inferred")
    with pytest.raises(Exception):
        Hop(method="m", edge="llm_inferred", justify_ref="not a ref")
    Hop(method="m", edge="llm_inferred", justify_ref="a/b.py:3-5")


def test_step_consistency():
    with pytest.raises(Exception):  # broken without directive
        TraceStep(assessment=StepAssessment.BROKEN, rationale="x")
    with pytest.raises(Exception):  # complete without source description
        TraceStep(assessment=StepAssessment.COMPLETE, rationale="x")
    TraceStep(assessment=StepAssessment.BROKEN,
              directive=TraceDirective(kind="writes_to", symbol="x"),
              rationale="x")
    TraceStep(assessment=StepAssessment.DEAD, rationale="honest dead end")
    TraceStep(assessment=StepAssessment.COMPLETE,
              source_description="req.query.name", rationale="x")


def test_hop_selection_ref_shape():
    with pytest.raises(Exception):
        HopSelection(candidate_id="c1", justify_ref="services/x.js line 5")
    HopSelection(candidate_id="c1", justify_ref="services/x.js:5-9")


# ---------------------------------------------------------------------------
# state machine with scripted LLM + fake engine
# ---------------------------------------------------------------------------

SINK = Sink(id="svc/db.py:10:py-sink-sqli", file="svc/db.py", line=10,
            rule="py-sink-sqli", vuln_type="sqli", name="execute")


def _brief(gap: Gap, chains=None, taint=None) -> InvestigationBrief:
    return InvestigationBrief(sink=SINK, semgrep={}, chains=chains,
                              taint=taint, gap=gap)


class FakeTools:
    def get_chain_snippets(self, sink_id):
        return []


class FakeEngine:
    """Pre-recorded directive -> rows; disk slices come from tmp files."""

    def __init__(self, tree: Path, scripted: dict | None = None):
        self.target = "fake"
        self.tree = tree
        self.tools = FakeTools()
        self.executions: list[dict] = []
        self.scripted = scripted or {}
        self.calls: list[str] = []

    def execute(self, directive, sink=None):
        sig = f"{directive.kind}:{directive.symbol}"
        self.calls.append(sig)
        rows = self.scripted.get(sig, [])
        self.executions.append({"tool": f"joern:{directive.kind}",
                                "args": {"symbol": directive.symbol},
                                "refs": [f"{r.get('file')}:{r.get('line')}"
                                         for r in rows if r.get("file")]})
        return rows, None

    def slice_source(self, file, start, end, max_lines=120):
        path = self.tree / file
        if not path.is_file():
            return "(no such file)"
        lines = path.read_text().splitlines()
        return "\n".join(f"{i:>4}: {lines[i - 1]}"
                         for i in range(max(1, start),
                                        min(end, len(lines)) + 1))


def _run(brief, engine, steps, verdict=None):
    """Drive trace_sink with a scripted LLM."""
    script = list(steps)
    seen_prompts: list[str] = []

    async def fake_step(prompt, budget):
        seen_prompts.append(prompt)
        assert script, "LLM called more times than scripted"
        return script.pop(0), 100

    async def fake_verdict(prompt, budget):
        return verdict or VerdictOut(
            is_vulnerable=True, confidence=0.9,
            reasoning="tainted reach", evidence=[],
            exploit_sketch="GET /x?q=1"), 50

    orig_step, orig_verdict = tracer._ask_step, tracer._ask_verdict
    tracer._ask_step, tracer._ask_verdict = fake_step, fake_verdict
    try:
        finding = asyncio.run(tracer.trace_sink(brief, engine, 100_000))
    finally:
        tracer._ask_step, tracer._ask_verdict = orig_step, orig_verdict
    return finding, seen_prompts


def test_complete_via_llm_hop(tmp_path):
    """GAP_NO_CHAIN: LLM orders callers_of, picks the candidate with a
    justify_ref, then completes."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "users.py").write_text(
        "def search():\n"
        "    name = request.args.get('q')\n"
        "    return run_query(name)\n")
    engine = FakeEngine(tmp_path, scripted={
        "callers_of:run_query": [{
            "method": "routes/users.py:<module>.search",
            "name": "search", "file": "routes/users.py",
            "line": 1, "line_end": 3, "route": "GET /search"}],
    })
    steps = [
        TraceStep(assessment=StepAssessment.BROKEN,
                  directive=TraceDirective(kind="callers_of",
                                           symbol="run_query",
                                           why="find callers"),
                  rationale="need callers"),
        TraceStep(resolve_candidates=[HopSelection(
                      candidate_id="c1", justify_ref="routes/users.py:1-3")],
                  assessment=StepAssessment.COMPLETE,
                  source_description="request.args q param",
                  rationale="reached the route handler"),
    ]
    finding, prompts = _run(_brief(Gap.GAP_NO_CHAIN), engine, steps)
    assert finding.verdict.is_vulnerable
    assert finding.stats["trace_status"] == "COMPLETE"
    llm_hops = [h for h in finding.stats["trace"]
                if h["edge"] == "llm_inferred"]
    assert len(llm_hops) == 1
    assert llm_hops[0]["justify_ref"] == "routes/users.py:1-3"
    assert finding.chain is not None
    assert finding.chain.route == "GET /search"
    assert finding.chain.path[0] == "routes/users.py:<module>.search"
    # round 2's envelope carried the candidate
    assert "c1" in prompts[1]


def test_dead_end_is_honest(tmp_path):
    """DEAD is accepted once a broad-recall probe has been tried."""
    engine = FakeEngine(tmp_path)
    steps = [
        TraceStep(assessment=StepAssessment.BROKEN,
                  directive=TraceDirective(kind="search_code",
                                           symbol="run_query",
                                           why="broad recall"),
                  rationale="no callers; search text"),
        TraceStep(assessment=StepAssessment.DEAD,
                  rationale="no callers exist"),
    ]
    finding, _ = _run(_brief(Gap.GAP_NO_CHAIN), engine, steps,
                      verdict=VerdictOut(is_vulnerable=False, confidence=0.8,
                                         reasoning="dead end", evidence=[]))
    assert not finding.verdict.is_vulnerable
    assert finding.stats["trace_status"] == "DEAD"


def test_dead_rejected_before_broad_recall(tmp_path):
    """The guardrail: a dead verdict with no find_call_sites/search_code
    probe yet is sent back, not accepted."""
    engine = FakeEngine(tmp_path)
    steps = [
        TraceStep(assessment=StepAssessment.DEAD,
                  rationale="premature give-up"),          # rejected
        TraceStep(assessment=StepAssessment.BROKEN,
                  directive=TraceDirective(kind="search_code",
                                           symbol="x", why="probe"),
                  rationale="probing"),
        TraceStep(assessment=StepAssessment.DEAD,
                  rationale="now honestly dead"),
    ]
    finding, prompts = _run(_brief(Gap.GAP_NO_CHAIN), engine, steps,
                            verdict=VerdictOut(is_vulnerable=False,
                                               confidence=0.8,
                                               reasoning="dead", evidence=[]))
    assert finding.stats["trace_status"] == "DEAD"
    assert "dead REJECTED" in prompts[1]  # feedback reached the LLM


def test_budget_exhaustion(tmp_path):
    """Every round orders fresh context (distinct directives, so the
    no-progress detector stays quiet); after MAX_TRACE_STEPS the state is
    BUDGET_OUT and the verdict still runs."""
    engine = FakeEngine(tmp_path, scripted={})
    steps = [TraceStep(assessment=StepAssessment.NEED_CONTEXT,
                       directive=TraceDirective(kind="search_code",
                                                symbol=f"nothing{i}",
                                                why="poke"),
                       rationale="need more")
             for i in range(20)]  # more than the cap
    finding, prompts = _run(_brief(Gap.GAP_NO_CHAIN), engine, steps)
    assert finding.stats["trace_status"] == "BUDGET_OUT"
    # exactly MAX_TRACE_STEPS_PER_SINK step calls, then the verdict call
    assert len(prompts) == config.MAX_TRACE_STEPS_PER_SINK


def test_no_progress_detection(tmp_path):
    engine = FakeEngine(tmp_path, scripted={"callers_of:foo": []})
    step = TraceStep(assessment=StepAssessment.BROKEN,
                     directive=TraceDirective(kind="callers_of",
                                              symbol="foo", why="again"),
                     rationale="still nothing")
    finding, _ = _run(_brief(Gap.GAP_NO_CHAIN), engine, [step] * 10)
    assert finding.stats["trace_status"] == "DEAD"
    assert "no progress" in finding.stats["trace_dead_reason"]


def test_bad_candidate_id_feeds_back(tmp_path):
    engine = FakeEngine(tmp_path, scripted={})
    steps = [
        TraceStep(resolve_candidates=[HopSelection(
                      candidate_id="c9", justify_ref="x.py:1-2")],
                  assessment=StepAssessment.DEAD,
                  rationale="give up"),
    ]
    finding, _ = _run(_brief(Gap.GAP_NO_CHAIN), engine, steps)
    # the bogus selection must not enter the chain
    assert all(h["edge"] == "engine" for h in finding.stats["trace"])


def test_ok_gap_skips_tracing(tmp_path):
    """OK sinks (chain + engine-confirmed taint) go straight to verdict."""
    chain = Chain(route="GET /x", entrypoint="routes/x.py:<module>.x",
                  path=["routes/x.py:<module>.x", "svc/db.py:<module>.run"])
    taint = TaintFlow(confirmed=True, flows=["x: a -> b"])
    engine = FakeEngine(tmp_path)
    finding, prompts = _run(_brief(Gap.OK, chains=[chain], taint=taint),
                            engine, steps=[])
    assert len(prompts) == 0  # verdict call is not a step prompt
    assert finding.stats["tool_calls"] == 1  # verdict only
    assert finding.verdict.is_vulnerable
    assert finding.confidence_level == "CONFIRMED"  # OK + confirmed taint
    assert engine.calls == []


# ---------------------------------------------------------------------------
# report.py llm_inferred-hop validation rule (M9.4)
# ---------------------------------------------------------------------------

def _finding_with_trace(tmp_path: Path, justify_ref: str) -> dict:
    (tmp_path / "svc").mkdir(exist_ok=True)
    (tmp_path / "svc" / "x.py").write_text(
        "def stageName(n):\n    pending = n\n")
    return {
        "sink": SINK.model_dump(),
        "chain": None,
        "verdict": {"is_vulnerable": True, "confidence": 0.9,
                    "reasoning": "r"},
        "confidence_level": "LIKELY",
        "evidence": [], "exploit_sketch": "GET /x", "sanitizer_notes": None,
        "stats": {"tool_log": [{"tool": "joern:callers_of",
                                "args": {"symbol": "stageName"},
                                "refs": ["svc/x.py:1"]}],
                  "trace": [{"method": "svc/x.py:<module>.stageName",
                             "file": "svc/x.py", "line": 1, "line_end": 2,
                             "edge": "llm_inferred",
                             "justify_ref": justify_ref}]},
    }


def test_llm_hop_justify_ref_validated(tmp_path):
    good = _finding_with_trace(tmp_path, "svc/x.py:1-2")
    assert report.validate_finding(good, tmp_path) == []

    bad = _finding_with_trace(tmp_path, "svc/x.py:50-60")  # out of range
    violations = report.validate_finding(bad, tmp_path)
    assert any("llm_inferred" in v for v in violations)

    missing = _finding_with_trace(tmp_path, "svc/nope.py:1-2")
    violations = report.validate_finding(missing, tmp_path)
    assert any("llm_inferred" in v for v in violations)


def test_llm_hop_violation_downgrades_confirmed(tmp_path):
    f = _finding_with_trace(tmp_path, "svc/x.py:50-60")
    f["confidence_level"] = "CONFIRMED"
    out = report.apply_validation([f], tmp_path)
    assert out[0]["confidence_level"] == "LIKELY"
    assert "downgraded" in out[0]["validation"]


# ---------------------------------------------------------------------------
# candidate shaping
# ---------------------------------------------------------------------------

def test_rows_to_candidates():
    rows = [{"method": "m.f", "file": "a.py", "line": 3, "line_end": 9,
             "code": "f(x)", "route": "GET /a"}]
    cands = rows_to_candidates(rows, "callers_of")
    assert len(cands) == 1
    c = cands[0]
    assert c.method == "m.f" and c.file == "a.py" and c.line == 3
    assert c.note == "GET /a"


# ---------------------------------------------------------------------------
# multi-chain verdicts (the py-sqli-01/02 FN: a sanitizer on the seeded chain
# must not veto the other chains reaching the same sink)
# ---------------------------------------------------------------------------

_CHAINS = [
    Chain(route="GET /users/<int:user_id>",
          entrypoint="routes/users.py:<module>.get_user",
          path=["routes/users.py:<module>.get_user",
                "svc/db.py:<module>.query_unsafe"]),
    Chain(route="GET /users/search",
          entrypoint="routes/users.py:<module>.search",
          path=["routes/users.py:<module>.search",
                "svc/db.py:<module>.query_unsafe"]),
]


def test_verdict_prompt_lists_all_chains(tmp_path):
    """The verdict envelope names every engine chain and the multi-chain
    rule, so one sanitized route cannot silently cover the others."""
    captured: list[str] = []

    async def fake_verdict(prompt, budget):
        captured.append(prompt)
        return VerdictOut(is_vulnerable=False, confidence=0.5,
                          reasoning="checked all chains", evidence=[]), 50

    engine = FakeEngine(tmp_path)
    orig = tracer._ask_verdict
    tracer._ask_verdict = fake_verdict
    try:
        asyncio.run(tracer.trace_sink(_brief(Gap.OK, chains=_CHAINS),
                                      engine, 100_000))
    finally:
        tracer._ask_verdict = orig
    assert len(captured) == 1
    prompt = captured[0]
    assert "REACHABLE CHAINS (2" in prompt
    assert "GET /users/<int:user_id>" in prompt
    assert "GET /users/search" in prompt


def test_exploitable_route_reanchors_chain(tmp_path):
    """A vulnerable verdict naming the second chain re-anchors the finding
    (and thus the verifier) to that chain, not the seeded-longest one."""
    verdict = VerdictOut(is_vulnerable=True, confidence=0.9,
                         reasoning="search chain has no sanitizer",
                         evidence=[], exploit_sketch="GET /users/search?q=x",
                         exploitable_route="GET /users/search")
    finding, _ = _run(_brief(Gap.OK, chains=_CHAINS), FakeEngine(tmp_path),
                      [], verdict=verdict)
    assert finding.chain is not None
    assert finding.chain.route == "GET /users/search"
    assert finding.chain.path == _CHAINS[1].path


def test_exploitable_chain_index_reanchors(tmp_path):
    """The 1-based chain index is the robust anchor (route labels vary)."""
    verdict = VerdictOut(is_vulnerable=True, confidence=0.9,
                         reasoning="chain 2 is unsanitized",
                         evidence=[], exploitable_chain=2)
    finding, _ = _run(_brief(Gap.OK, chains=_CHAINS), FakeEngine(tmp_path),
                      [], verdict=verdict)
    assert finding.chain is not None
    assert finding.chain.route == "GET /users/search"
    assert finding.chain.path == _CHAINS[1].path


def test_no_exploitable_route_keeps_seeded_chain(tmp_path):
    verdict = VerdictOut(is_vulnerable=True, confidence=0.9,
                         reasoning="tainted", evidence=[])
    finding, _ = _run(_brief(Gap.OK, chains=_CHAINS), FakeEngine(tmp_path),
                      [], verdict=verdict)
    assert finding.chain is not None
    assert finding.chain.path[0] in {c.path[0] for c in _CHAINS}
