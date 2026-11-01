"""Contracts for the LLM-guided trace-continuation state machine (A-class v2).

The tracer (tracer.py) owns a TraceState per sink and drives a structured
ping-pong: the LLM answers ONE TraceStep per round (candidate resolution +
completeness assessment + at most one directive), the orchestrator executes
the directive through trace_engine.py and feeds the results back next round.
The LLM never touches joern syntax — TraceDirective.kind is a closed menu
translated to engine queries by the orchestrator.

Anti-hallucination bottom line (plan M9.4): every hop the LLM adds
(edge == "llm_inferred") must carry a justify_ref ("file:start-end") that
report.validate_finding can resolve on disk.
"""

from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator

from .contracts import Evidence, Sink, TaintFlow

# Closed directive menu. joern-backed kinds are executed by trace_step.sc;
# read_file/search_code are disk/ripgrep reads (scrubbed) so the LLM can
# "order" extra context instead of roaming by itself.
DIRECTIVE_KINDS = ("callers_of", "writes_to", "reads_of", "find_call_sites",
                   "trace_back", "methods_in_file", "read_file", "search_code")

_REF_SHAPE = __import__("re").compile(
    r"^[\w./-]+\.(?:py|js|ts|java|cs|jsp|pl|pm|php):\d+(?:-\d+)?$")


class Edge(str, Enum):
    ENGINE = "engine"                # hop came from a joern chain
    LLM_INFERRED = "llm_inferred"    # hop the LLM picked from candidates


class Hop(BaseModel):
    """One link in the traced path, entrypoint-side first when assembled."""

    method: str              # method fullName or "file:function" label
    file: str = ""
    line: int = 0
    line_end: int = 0        # enclosing-method end line, when known
    edge: Edge = Edge.ENGINE
    justify_ref: str | None = None  # "file:start-end", required for LLM hops

    @model_validator(mode="after")
    def _llm_hop_needs_justify(self):
        if self.edge == Edge.LLM_INFERRED:
            if not self.justify_ref or not _REF_SHAPE.match(self.justify_ref):
                raise ValueError(
                    "llm_inferred hop requires justify_ref as 'file:start-end' "
                    f"(got {self.justify_ref!r})")
        return self


class Candidate(BaseModel):
    """One engine-returned possible continuation, shown to the LLM for
    disambiguation. `id` is assigned by the orchestrator (c1, c2, ...)."""

    id: str = ""
    kind: str = ""           # directive kind that produced it
    method: str = ""         # enclosing method fullName
    file: str = ""
    line: int = 0
    line_end: int = 0
    code: str = ""           # the call-site / assignment line
    note: str = ""


class TraceDirective(BaseModel):
    """The LLM's 'next step' order to the engine. symbol/file/line usage
    depends on kind: callers_of/writes_to/reads_of/find_call_sites/
    trace_back take symbol; read_file takes file (+line); search_code takes
    symbol as the ripgrep pattern; methods_in_file takes file."""

    kind: str
    symbol: str = ""
    file: str | None = None
    line: int | None = None
    why: str = ""

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, v: str) -> str:
        if v not in DIRECTIVE_KINDS:
            raise ValueError(f"unknown directive kind {v!r} "
                             f"(allowed: {', '.join(DIRECTIVE_KINDS)})")
        return v


class HopSelection(BaseModel):
    """The LLM accepting one candidate as the next hop. justify_ref is the
    anti-hallucination anchor: the code lines that justify this edge."""

    candidate_id: str
    justify_ref: str         # "file:start-end" the LLM actually saw
    note: str = ""

    @field_validator("justify_ref")
    @classmethod
    def _ref_shape(cls, v: str) -> str:
        if not _REF_SHAPE.match(v.strip()):
            raise ValueError(f"justify_ref must be 'file:start-end', got {v!r}")
        return v.strip()


class StepAssessment(str, Enum):
    COMPLETE = "complete"          # path reaches an attacker-controlled source
    BROKEN = "broken"              # gap identified; directive says where to dig
    NEED_CONTEXT = "need_context"  # undecidable; directive orders more code
    DEAD = "dead"                  # honest dead end, no continuation exists


class TraceStep(BaseModel):
    """The ONE form the LLM fills per round: resolve last round's candidates,
    assess completeness, and (unless complete/dead) issue one directive."""

    resolve_candidates: list[HopSelection] = Field(default_factory=list)
    reject_reason: str | None = None   # why all candidates were rejected
    assessment: StepAssessment
    directive: TraceDirective | None = None
    source_description: str | None = None  # required when complete
    rationale: str = ""

    @model_validator(mode="after")
    def _consistent(self):
        if self.assessment in (StepAssessment.BROKEN,
                               StepAssessment.NEED_CONTEXT) \
                and self.directive is None:
            raise ValueError(f"assessment={self.assessment.value} requires "
                             "a directive (where should the engine dig next?)")
        if self.assessment == StepAssessment.COMPLETE \
                and not (self.source_description or "").strip():
            raise ValueError("assessment=complete requires source_description "
                             "(what attacker-controlled input feeds the path)")
        return self


class TraceStatus(str, Enum):
    TRACING = "TRACING"
    COMPLETE = "COMPLETE"
    DEAD = "DEAD"
    BUDGET_OUT = "BUDGET_OUT"


class TraceState(BaseModel):
    """The dossier the orchestrator holds for one sink (serialized into the
    finding's stats for auditability)."""

    sink: Sink
    hops: list[Hop] = Field(default_factory=list)  # head = closest to source
    frontier: str = ""         # method label where tracing currently sits
    status: TraceStatus = TraceStatus.TRACING
    taint: TaintFlow | None = None
    steps: int = 0
    dead_reason: str | None = None
    source_description: str | None = None


class VerdictOut(BaseModel):
    """The LLM's semantic verdict once the path is as complete as it gets:
    is attacker-controlled input really reaching the sink's dangerous
    argument without effective sanitization?"""

    is_vulnerable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    evidence: list[Evidence] = Field(default_factory=list)
    exploit_sketch: str | None = None
    sanitizer_notes: str | None = None
    # When several engine chains reach the sink, a vulnerable verdict is
    # about ONE exploitable chain — identify it so the finding (and the
    # verifier) is anchored to that chain, not to an arbitrary one.
    # exploitable_chain is the 1-based index into the REACHABLE CHAINS
    # list (robust); exploitable_route is the free-text route label
    # (report sugar, fuzzy-matched as a fallback).
    exploitable_chain: int | None = None
    exploitable_route: str | None = None
