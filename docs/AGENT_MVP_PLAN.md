# AI SAST Agent MVP 改进计划

> **2026-09-05 注**：jsp-legacy target 已按用户决定从仓库删除（含
> `scripts/jsp_to_java.py`）。本文档中所有 JSP 相关内容（§0 基线行、
> M6/M7 的 5-target 口径）均为历史记录；当前有效 target 为 4 个
> （java-spring / js-ts-express / python-flask / csharp-aspnet）。

目标：把现有的 Semgrep + Joern 一次性流水线改造成基于 **pydantic-ai** 的
autonomous investigation agent。核心转变：流水线的各阶段从"固定编排的管道"
降级为"agent 手里的工具"，由 LLM 根据中间结果动态决定调查路径。

本文档是实现规格，可直接交给 kimi code 分阶段执行。

## 0. 现状盘点（改造的基础）

已有资产（全部保留，不重写）：

| 资产 | 角色 | agent 化后的定位 |
|---|---|---|
| `analysis/rules/sinks-*.yml` | Semgrep sink 规则（4 语言 + JSP 复用 java） | 工具 `run_semgrep` 的规则集 |
| `scripts/semgrep_to_sinks.py` | Semgrep JSON → sink 清单 | 工具内部调用 |
| `analysis/joern/backward_from_sinks.sc` | sink→入口点调用链回溯（CHAINS_JSON） | 工具 `get_chains` |
| `analysis/joern/taint_confirm.sc` | DFG 污点确认（JSONL） | 工具 `get_taint_flows` |
| `analysis/joern/find_entrypoints.sc` | HTTP 入口枚举 | 工具 `list_entrypoints`（B 类备用） |
| `analysis/joern/forward_from_entrypoints.sc` | 入口点向下前向追踪 | 工具（B 类备用，MVP 不接） |
| `analysis/joern/extract_chain_snippets.sc` | 链上源码片段提取（SRC_ROOT 磁盘切片） | 工具 `get_chain_snippets` |
| `scripts/repo_map.py` | tree-sitter 仓库地图（路由表/符号/引用图） | agent 的开局上下文 |
| `scripts/llm_judge_sink_chains.py` | pydantic-ai + DeepSeek 判定器（A 类） | 判定 prompt 与 Verdict 模型的来源 |
| `scripts/chain_report.py` | 链级 CONFIRMED/UNCONFIRMED 报告 | 基线指标来源 |
| `targets/*/ground_truth.json` | 5 个项目的标注 | **仅用于回归评测，agent 运行时不可见** |

已知引擎盲区（agent 动态下钻的首要目标，见 `analysis/LIMITATIONS.md`）：
- JS 模块级变量的跨文件污点（`js-sqli-02`：taint_confirm 无法确认）
- C# 跨文件流入 `Services/` 后 DFG 丢失（`cs-cmdi-02`、`cs-path-traversal-01`）
- 调用链缺失字段写入点（sibling store call 不在 backward 链上）

当前基线（回归门禁的参照，来自 `PROGRESS.md`）：
- 链级：py 22/25、java 21/22、js 22/28、cs 18/25 CONFIRMED
- JSP 端到端：LLM 判定 A 类 10/10、B 类 7/7、SAFE 样本 0 FP
- taint_confirm：JSP 15/16 sinks CONFIRMED

## 1. MVP 范围（明确不做什么）

**做**：A 类（sink 驱动的 8 类注入漏洞）的 agent 化调查循环。

**不做**（后续阶段）：
- B 类（逻辑漏洞）的假设驱动 agent 化——MVP 阶段继续用
  `llm_judge_entrypoints.py` 批处理
- 规则自进化（agent 现场写 Semgrep 规则）
- 跨扫描记忆层、canary 注入
- 平台化（队列、缓存、CI 集成）

理由：A 类链条的 UNCONFIRMED/NO_CHAIN 残余 case 是流水线最明显的短板，
也是"agent 动态下钻"价值最容易被 benchmark 验证的地方。

## 2. 目标架构

```
                    ┌──────────────────────────────────┐
                    │  run_agent.py (CLI)              │
                    │  uv run agent/run_agent.py       │
                    │    --target targets/python-flask │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  Planner（同一次 agent 会话内）    │
                    │  1. 读 repo_map + sink 清单       │
                    │  2. 按风险排序，逐 sink 调查       │
                    └──────────────┬───────────────────┘
                                   │ per-sink 调查循环（有预算上限）
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
┌───────▼───────┐        ┌─────────▼────────┐       ┌─────────▼────────┐
│ 确定性初筛     │        │ 动态下钻（核心）   │       │ 对抗复核          │
│ get_chains    │        │ read_function    │       │ attacker 视角:    │
│ get_taint_    │──失败──│ search_code      │       │ 构造触发请求      │
│ flows         │NO_CHAIN│ joern_query      │       │ defender 视角:    │
│               │UNCONF. │ (即席 CPG 查询)   │       │ 找 sanitizer      │
└───────────────┘        └──────────────────┘       └──────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  Finding（结构化输出）             │
                    │  verdict + confidence + 证据包    │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────▼───────────────────┐
                    │  报告 + benchmark 回归评分         │
                    └──────────────────────────────────┘
```

关键设计决策：
- **单 agent + 工具循环**，不做多 agent 编排。MVP 用 pydantic-ai 的
  `Agent` + `@agent.tool` 即可；planner/worker 拆分留给后续。
- **确定性初筛先行**：每个 sink 先跑现成的 chain + taint 工具（便宜），
  只有 NO_CHAIN / UNCONFIRMED 的 case 才进入动态下钻（贵）。这就是
  "流水线解决 80%，agent 啃 20%"的落地方式。
- **判定逻辑不进工具**：工具只返回事实（链、流、源码），verdict 完全由
  LLM 产出，便于在 benchmark 上对比"流水线判定 vs agent 判定"。

## 3. 代码结构（新增，不动现有文件）

```
agent/
├── sast_agent/
│   ├── __init__.py
│   ├── config.py       # DEEPSEEK_* env（复用 llm_judge_sink_chains.py 的
│   │                   # 加载逻辑：.env → ~/Code/agent-demo/.env 兜底）、
│   │                   # 预算常量（见 §6）
│   ├── contracts.py    # pydantic 模型：Sink / Chain / TaintFlow /
│   │                   # Evidence / Verdict / Finding（见 §4）
│   ├── pipeline.py     # 确定性初筛编排：semgrep → sinks → CPG →
│   │                   # backward → taint_confirm（子进程调用，带缓存目录
│   │                   # workspace/agent-cache/<target>/）
│   ├── tools.py        # pydantic-ai 工具集（见 §5）
│   ├── investigator.py # per-sink 调查 agent（system prompt + 工具 + 预算）
│   ├── verifier.py     # 对抗复核（attacker/defender 两轮独立判定）
│   └── report.py       # findings JSONL + Markdown 报告 + 对 ground truth
│                       # 的评分（复用 llm_judge_sink_chains.py 的匹配逻辑：
│                       # file+function 匹配、_jsp.java → .jsp 归一化）
└── run_agent.py        # CLI 入口（PEP 723 inline deps，uv run）
```

依赖（PEP 723）：`pydantic-ai-slim[openai]>=2.0.0`、`pydantic>=2`、
`python-dotenv`、`httpx[socks]`——与现有 judge 脚本保持一致。
运行前提：本机已有 `semgrep`、`joern`（`joern-parse`/`joern --script`），
与现状相同。

## 4. 数据契约（contracts.py）

```python
class Sink(BaseModel):
    id: str                 # "file:line:rule"
    file: str; line: int; rule: str; vuln_type: str
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
    confidence: float       # 0..1
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
```

`confidence_level` 的映射规则（report.py 中实现，不是 LLM 自由发挥）：
- CONFIRMED：链存在 ∧（DFG 确认 ∨ 下钻补齐了完整污点路径）∧ verifier
  攻击视角构造成功 ∧ 防御视角未找到有效 sanitizer
- LIKELY：链存在，污点路径部分确认（引擎盲区或下钻不完整）
- SUSPICIOUS：只有 Semgrep 形状命中，链不通或证据矛盾

## 5. 工具集（tools.py）

每个工具都是对现有脚本/命令的薄封装，**只返回事实，不做判定**。
所有写操作限定在 `workspace/agent-cache/`，targets 只读。

| 工具 | 实现 | 返回 |
|---|---|---|
| `get_repo_map()` | `uv run scripts/repo_map.py <target> --json` | 路由表 + 符号摘要（截断到预算内） |
| `run_semgrep()` | `semgrep --config analysis/rules/sinks-<lang>.yml --json` → `semgrep_to_sinks.py` | Sink 列表 |
| `get_chains(sink_id)` | `SINKS_FILE=... CHAINS_JSON=... joern --script backward_from_sinks.sc <cpg>`（缓存） | Chain 列表（可能空） |
| `get_taint_flows(sink_id)` | `taint_confirm.sc` JSONL | TaintFlow |
| `get_chain_snippets(sink_id)` | `extract_chain_snippets.sc`（SRC_ROOT=target） | 链上各函数源码 |
| `read_function(file, start, end)` | 直接磁盘切片 | 源码文本 |
| `search_code(pattern, glob?)` | ripgrep 子进程 | 命中列表（file:line + 上下文 2 行） |
| `joern_query(description, scala_expr)` | 把查询包进临时 .sc（含预置 import 和 JSON 打印模板），`joern --script` 执行 | JSON 结果（行数上限） |
| `list_entrypoints()` | `find_entrypoints.sc` | 入口列表（主要给 prompt 做全局感知） |
| `submit_finding(finding)` | 校验并记录 | 结束当前 sink 的调查 |

`joern_query` 是"agent 自己写即席 CPG 查询"的能力入口，也是风险点：
- 用模板包裹：只允许返回 JSON 序列化的节点投影（file/line/name/code），
  不允许文件写、网络、cpg 修改类调用（模板里做关键字黑名单 +
  输出截断）。
- MVP 阶段 scala_expr 限制在 500 字符内，失败 2 次后工具返回
  "放弃即席查询，改用 read_function/search_code"的提示。

CPG 构建缓存：`workspace/agent-cache/<target>/cpg.bin`，
mtime 早于 targets 源码最新 mtime 才重建（joern-parse 很慢，必须有缓存）。

## 6. 调查循环（investigator.py）

System prompt 骨架（在现有 judge 的 SYSTEM_PROMPT 基础上扩展）：

```
You are a senior application-security engineer investigating suspected
vulnerabilities in a web application. For each sink you receive the Semgrep
match, the call-chain and taint-flow results from Joern, and source snippets.

Your job:
1. If the chain is complete and taint CONFIRMED, verify semantically
   (sanitizers, input controllability) and submit the finding.
2. If NO_CHAIN or UNCONFIRMED, DO NOT give up — drill down:
   - read_function / search_code to find where the tainted value is stored
     (field writes, module variables, sibling calls missing from the chain);
   - joern_query for ad-hoc checks (callers of X, writes to field Y);
   - piece the path together across files manually, like "go to definition".
3. Then run the adversarial check on yourself: construct a concrete
   trigger request (attacker) and look for effective sanitizers (defender).
4. submit_finding with honest confidence: a partial path with gaps is
   LIKELY, not CONFIRMED.

Constraints:
- Base every claim on code you actually saw; cite file:line for each claim.
- Never invent functions or sinks not present in tool results.
- Budget: at most {max_tool_calls} tool calls for this sink. If you exhaust
  the budget with an incomplete path, submit with confidence_level LIKELY
  and note the gap.
```

预算（config.py，MVP 默认值，benchmark 后调）：
- `MAX_TOOL_CALLS_PER_SINK = 25`
- `MAX_TOTAL_LLM_TOKENS = 2_000_000`（pydantic-ai `UsageLimits`）
- `MAX_JOERN_QUERY_RETRIES = 2`
- 单 sink 判定超时 180s

循环控制：pydantic-ai 的 `output_type=Finding` 不作为直接终止——用
`submit_finding` 工具显式提交（便于 stats 记录和预算拦截），agent run
结束后从 tool call 记录里取 Finding。

## 6A. 动态下钻机制（M3 详细设计）

下钻不是 agent 自由发挥，而是"检测缺口类型 → 按 playbook 选工具序列 →
证据记账 → 机械校验"。四层：

### 信号层：InvestigationBrief 缺口分类

pipeline.py 把确定性初筛结果包装成带缺口语义的 brief：

- `GAP_NO_CHAIN`：backward 回溯未达入口点
- `GAP_FLOW_DEAD`：链存在但 taint_confirm 未确认，附 sink 侧函数源码
- `GAP_MISSING_STORE`：链/流存在但字段写入点不在链上
- `OK`：直接语义判定，不触发下钻（下钻工具对 OK 的 sink 不可用）

### 工具层

`joern_query` 在 MVP 改为**参数化模板**（不做自由 Scala）：

- `callers_of(methodName)` — X 的全部调用者
- `writes_to(varName)` — 对变量/字段的全部赋值点
- `reads_of(varName)` — 全部读取点
- `methods_in_file(file)` — 辅助

自由查询为后续阶段；模板化规避了 LLM 不熟 joern Scala DSL 的风险和
注入面。

### 策略层 playbook（写进 investigator system prompt）

`GAP_FLOW_DEAD` 标准动作（jump-on-store 接力）：

1. `read_function` 读 sink 侧函数，定位流死点处的外部变量
2. `search_code(var)` 找全部写入点（模块变量/字段的 store 点）
3. `search_code(storeFn)` 找写入函数的调用点，接回入口方向
4. 接通后逐段记录 evidence（file:line），submit 注明"人工接力补齐
   （引擎盲区）"

`GAP_NO_CHAIN` 标准动作（文本级 go-to-definition）：从 sink 向上
search 调用点文本 → 读目标文件 → 重复，直到接上 repo_map 路由表里的
入口；链终点非入口时用路由表反查归属。

靶子验收（M3 必过）：
- `js-sqli-02`：DFG 死在模块变量 `pendingName`（userService.js:5 声明、
  stageName:8 写入、findStaged:13 读取），agent 须补出
  `req.query.name → stageName → pendingName → findStaged → db.query`
  完整路径；
- `cs-cmdi-02`：DFG 死在 `Services/ToolService.cs` 的字段 `_target`，
  同上接回 controller。

### 校验层：report.py 链路连续性检查

对每条下钻补出的路径：相邻 evidence 的 file:line 必须真实存在于磁盘、
引用行与工具返回一致、段间至少有一个工具结果支撑跳转。造假或断档 →
自动降 LIKELY 并标注 `evidence gap`。

### 循环控制

- 仅 `GAP_*` sink 可调用下钻工具
- `joern_query` 连续失败 2 次 → 工具返回强制改用手动接力
- 预算剩 2 次调用时注入"立即 submit"系统消息

## 7. 对抗复核（verifier.py）

对 investigator 判 `is_vulnerable=true` 的 finding 追加两轮独立判定
（新 agent 实例，共享 evidence 但不共享推理过程）：
- **attacker**：给出具体的触发 HTTP 请求（方法、路径、参数、payload），
  逐步说明数据如何到达 sink。构造失败 → 降级。
- **defender**：在 evidence + 允许补充 read_function/search_code 的前提
  下寻找有效 sanitizer / 鉴权 / 类型约束。找到 → 降级或否决。

两轮结果与初判合并进 `confidence_level`（规则见 §4）。
MVP 里 verifier 允许使用 read/search 工具，但不允许 joern_query。

## 7A. Category B 的 agent 化（第二阶段设计，M6–M8）

B 类与 A 类的根本差异：锚点不是 sink（危险函数的存在），而是"该在的
检查不在"（IDOR 缺归属校验、越权缺角色检查、批量赋值缺字段白名单）。
证据形态从"找到一条路径"变成"证明一个缺席"，因此队列来源、验证手法、
完整性约束都不同——但复用同一个 investigator agent 与工具层，只换
队列和 playbook。

### 队列来源：planner 生成假设清单

planner（独立 agent run，或同一 run 的首阶段）读 repo_map 路由表 +
符号摘要，按启发式给每条路由挂疑似类别，产出 hypothesis queue：

| 路由特征 | 假设类别 |
|---|---|
| 路径带 `:id`/`<id>` 参数，handler 无鉴权装饰器 | idor / broken-access-control |
| POST/PUT 请求体整体绑定模型 | mass-assignment |
| 读后写余额/库存类操作 | race-condition |
| 登录/token/重置密码路由 | auth-flaws |
| role 判断来源可疑 | priv-esc |
| 金额/数量/状态流转 | business-logic |

每条假设 = {route, entrypoint, vuln_type, 触发特征, 初判理由}，
经 `submit_hypotheses` 工具入队。

### Worker playbook：缺席对比法

1. `get_forward_slice(entrypoint)`：handler + 全部下游函数源码
   （新增工具，封装 `forward_from_entrypoints.sc` +
   `extract_entrypoint_snippets.sc`）
2. 在 slice 内找该类别的"应有检查"（归属判断/角色判断/字段过滤/锁）
3. 没找到 → `search_code` 全仓库找同类检查的惯用法
   （`login_required` / `requireRole` / `current_user.id ==` 模式）
4. 对比定案：别的路由有而这条没有 → 缺席成立；全仓库都没有 → 查
   app 初始化/中间件注册处（guard 可能统一挂载）；框架层确有统一
   处理 → defender 证据，降级

verifier 角色不变：attacker 构造具体越权请求（"以用户 1 身份
GET /users/2"），defender 搜索中间件/框架层的隐藏 guard。

### 完整性约束：taxonomy 覆盖检查表

planner 必须对照 7 类 B 类 taxonomy 逐类报告"考察了几条路由、为何
排除"，写入报告审计区——无 ground truth 环境下这是 B 类召回率的唯一
可见保障。

### 里程碑（接 §8 的 M5 之后）

- **M6（1 天）**：planner + `submit_hypotheses` + `get_forward_slice`
  工具。验收：5 个 target 上假设清单覆盖 ground truth 全部 B 类条目
  对应的路由（用 ground truth 只做覆盖率校验，不喂给 agent）。
- **M7（2 天）**：B 类 worker playbook + 缺席对比。验收：每 target
  B 类 recall ≥ 基线（现 `llm_judge_entrypoints.py` 为 7/7），SAFE
  样本 0 新增 FP；每条 CONFIRMED 附"缺席对比"证据（对比对象的路由和
  检查代码位置）。
- **M8（0.5 天）**：taxonomy 覆盖检查表入报告；回归门禁扩展到 B 类。

## 8. 里程碑与验收标准

### M0：基线固化（0.5 天）
- 脚本 `agent/run_baseline.py`：对每个 target 跑确定性流水线
  （semgrep → chains → taint → 现有 LLM judge），输出基线 JSON 存
  `workspace/baseline/`。
- 验收：5 个 target 全部跑通，数字与 PROGRESS.md 记录一致
  （py/java/js/cs 链级 CONFIRMED 数、JSP 的 A 类 10/10）。

### M1：工具层（1-2 天）
- 实现 contracts.py / pipeline.py / tools.py，含 CPG 缓存。
- 验收：对 `targets/python-flask`，每个工具能被独立调用并返回正确事实
  （get_chains 对 `db.py` 的 query sink 返回非空链；get_taint_flows 对
  `get_user` 链返回 confirmed=true）。写一个 smoke 脚本逐一断言。

### M2：单 sink 调查 agent（2 天）
- 实现 investigator.py + report.py，先不接下钻工具（只有
  chains/taint/snippets + submit_finding）。
- 验收：python-flask 上 A 类 recall ≥ 基线；SAFE 样本 0 FP；产出
  findings JSONL + Markdown 报告；每条 finding 有完整 stats。

### M3：动态下钻（2-3 天，核心里程碑）
- 接入 read_function / search_code / joern_query。
- 验收（用已知盲区做靶子）：
  - `js-sqli-02`（模块变量跨文件）：agent 必须自己定位 `stageName` 的
    写入点并给出完整污点路径，verdict 从基线的 UNCONFIRMED 提升为
    CONFIRMED/LIKELY 且证据链完整；
  - `cs-cmdi-02` / `cs-path-traversal-01`（C# 跨文件入 Services）：
    同上；
  - 全量回归：5 个 target 的 A 类 recall 不低于基线，SAFE 样本 FP
    不增加，总 token 消耗在预算内。

### M4：对抗复核 + 置信度分级（1-2 天）
- 实现 verifier.py 和 CONFIRMED/LIKELY/SUSPICIOUS 映射。
- 验收：报告按置信度分级输出；故意把一个 SAFE 样本的 sink 喂给
  investigator，verifier 的 defender 视角必须能拦截（FP 不进入
  CONFIRMED 栏）。

### M5：批量化 + 回归门禁（1 天）
- run_agent.py 支持 `--target all`，并行度 2（joern 内存大，别开多）。
- `agent/run_baseline.py --compare`：与基线 JSON 对比，recall 下降或
  SAFE FP 新增即非零退出，作为每次改动的门禁。
- 验收：全量一键跑通，报告落盘 `workspace/agent-reports/<date>/`。

## 9. 红线（写进 agent 的硬约束，不是建议）

1. **agent 进程对 `targets/` 只读**。工具层在 OS 层面不做强制，但所有
   工具函数拒绝 targets 内的写路径；joern_query 模板禁用文件写 API。
2. **ground truth 隔离**：agent 的任何工具都不能读到
   `ground_truth.json` / `GROUND_TRUTH.md`（search_code 和
   read_function 对这两个文件名直接拒绝）；评分只在 report.py 里、
   agent 跑完之后做。VULN:/SAFE: 注释泄漏检查沿用现有的 snippet 校验。
3. **不为通过率改规则**：M3/M4 期间若 benchmark 不达标，只允许改
   prompt、工具返回格式、预算——不改 `analysis/rules/`、不改
   ground_truth、不"硬化"target 代码（AGENTS.md 既有约束）。
4. **诚实性兜底**：报告里 CONFIRMED 的每条 finding 必须附带至少一条
   `exploit_sketch` 和全部 file:line 引用；缺引用的 finding 在
   report.py 自动降级。

## 10. 后续阶段（不在本 MVP，先记下）

- ~~B 类假设驱动 agent 化~~ 已展开为 §7A（M6–M8），与本 MVP 共用
  investigator 和工具层
- 规则自进化：agent 发现内部封装 sink → 候选规则 → 沙盒验证 → 入库
- 生产无 ground truth 运营：置信度分级 + 人工分诊反馈回流 + canary
  注入测召回；确认的野外漏洞镜像回 benchmark（AGENTS.md 既有流程）
- CPG 构建队列化与增量缓存（平台化）
- B 类 worker 并行化（M7 稳定后按路由切分并行）
