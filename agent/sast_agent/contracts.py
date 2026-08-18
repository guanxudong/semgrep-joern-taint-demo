"""Data contracts for the SAST agent (AGENT_MVP_PLAN.md §4 + §6A 信号层).

Tools return facts shaped by these models; the verdict logic lives in the
investigator/verifier (M2+), never in the tools themselves.
"""

from enum import Enum

from pydantic import BaseModel, Field


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


class InvestigationBrief(BaseModel):
    """Per-sink screening result handed to the investigator (§6A)."""

    sink: Sink
    semgrep: dict = Field(default_factory=dict)  # raw semgrep metadata (cwe, matched line)
    chains: list[Chain] | None = None
    taint: TaintFlow | None = None
    gap: Gap
