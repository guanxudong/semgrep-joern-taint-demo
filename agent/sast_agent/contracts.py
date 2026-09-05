"""Data contracts for the SAST agent (AGENT_MVP_PLAN.md §4 + §6A 信号层).

Tools return facts shaped by these models; the verdict logic lives in the
investigator/verifier (M2+), never in the tools themselves.
"""

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Sink(BaseModel):
    id: str                 # "file:line:rule"
    file: str
    line: int
    rule: str
    vuln_type: str
    name: str               # sink 函数名


class Chain(BaseModel):
    route: str | None
    entrypoint: str         # method fullName
    path: list[str]         # entrypoint → ... → sink 所在方法


class TaintFlow(BaseModel):
    confirmed: bool
    flows: list[str]        # 可读的流路径描述


class Evidence(BaseModel):
    kind: str               # "chain" | "taint_flow" | "code_read"
                            # | "joern_query" | "exploit_sketch"
                            # | "absence_comparison" (category B, §7A)
    summary: str
    refs: list[str]         # "file:start-end" 可核查位置


class Verdict(BaseModel):
    is_vulnerable: bool
    confidence: float = Field(ge=0.0, le=1.0)  # 0..1
    reasoning: str          # 2-4 句：污点路径 + 为什么可利用/不可利用


class Finding(BaseModel):
    sink: Sink
    chain: Chain | None
    verdict: Verdict
    confidence_level: str   # "CONFIRMED" | "LIKELY" | "SUSPICIOUS"
    evidence: list[Evidence]
    exploit_sketch: str | None   # attacker 视角构造的触发请求
    sanitizer_notes: str | None  # defender 视角结论
    stats: dict             # tool_calls / tokens / 触发的下钻动作


class Gap(str, Enum):
    """Deterministic-screening gap classification (§6A 信号层)."""

    OK = "OK"                          # 直接语义判定，不触发下钻
    GAP_NO_CHAIN = "GAP_NO_CHAIN"      # backward 回溯未达入口点
    GAP_FLOW_DEAD = "GAP_FLOW_DEAD"    # 链存在但 taint_confirm 未确认
    GAP_MISSING_STORE = "GAP_MISSING_STORE"  # 字段写入点不在链上


# Category-B taxonomy (§7A): the 7 non-sink classes the planner hypothesizes.
B_VULN_TYPES = ("idor", "business-logic", "race-condition", "priv-esc",
                "mass-assignment", "broken-access-control", "auth-flaws")


class Hypothesis(BaseModel):
    """One planner-generated category-B suspicion (§7A 队列来源).

    Evidence shape is "a check that should be there is absent", so the queue
    entry is a route + expected class + why the route looks suspicious."""

    route: str              # "GET /users/<id>" or "JSP /X.jsp"
    entrypoint: str         # "file:function" or method fullName
    vuln_type: str          # one of B_VULN_TYPES (validated below)
    trigger_features: str   # 触发特征: the route traits that matched a heuristic
    rationale: str          # 初判理由: why this route may miss the check

    @field_validator("vuln_type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        if v not in B_VULN_TYPES:
            raise ValueError(f"unknown category-B vuln_type {v!r} "
                             f"(allowed: {', '.join(B_VULN_TYPES)})")
        return v


class ExcludedRoute(BaseModel):
    """One route the planner considered for a class but did not submit (§7A
    完整性约束): the exclusion reason is the audit trail."""

    route: str              # "GET /users/<id>" (digest route label)
    reason: str             # 为何排除: guard seen / trait absent / ...


class TaxonomyEntry(BaseModel):
    """Per-class accounting for the taxonomy coverage checklist (§7A 完整性
    约束, M8): in a no-ground-truth environment this is the only visible
    guarantee of category-B recall."""

    vuln_type: str          # one of B_VULN_TYPES (validated below)
    routes_examined: int = Field(ge=0)  # how many routes the planner looked at
    submitted: list[str] = Field(default_factory=list)   # routes hypothesized
    excluded: list[ExcludedRoute] = Field(default_factory=list)

    @field_validator("vuln_type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        if v not in B_VULN_TYPES:
            raise ValueError(f"unknown category-B vuln_type {v!r} "
                             f"(allowed: {', '.join(B_VULN_TYPES)})")
        return v


class BFinding(BaseModel):
    """One worker verdict over a category-B hypothesis (§7A, M7).

    The A-class Finding anchors on a sink; the B-class evidence shape is an
    ABSENT check, so the anchor is the planner's Hypothesis (echoed back
    verbatim) plus the absence-comparison evidence."""

    hypothesis: Hypothesis  # 原样回填 (route/entrypoint/vuln_type/...)
    verdict: Verdict
    confidence_level: str   # "CONFIRMED" | "LIKELY" | "SUSPICIOUS"
                            # (report 机械映射，非 LLM 填)
    evidence: list[Evidence]
    exploit_sketch: str | None = None   # attacker 视角的具体越权请求
    sanitizer_notes: str | None = None  # defender 视角结论（middleware/框架层 guard）
    comparison: str | None = None       # 缺席对比结论: 对比对象路由 + 检查代码
                                        # file:line（CONFIRMED 必填）
    stats: dict = Field(default_factory=dict)  # tool_calls / tokens / verifier


class InvestigationBrief(BaseModel):
    """Per-sink screening result handed to the investigator (§6A)."""

    sink: Sink
    semgrep: dict = Field(default_factory=dict)  # raw semgrep metadata (cwe, matched line)
    chains: list[Chain] | None = None
    taint: TaintFlow | None = None
    gap: Gap
