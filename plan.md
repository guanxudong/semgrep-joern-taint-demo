# AI SAST 自我改进路线图（post-MVP）

> 2026-09-10 制定。M0–M8 已全部关闭（规格 `docs/AGENT_MVP_PLAN.md`，执行记录
> `agent/HANDOFF.md`），benchmark 在天花板：A 类 recall 4/4 target 10/10、
> B 类 7/7、SAFE FP 仅基线自带四个。本计划是 post-MVP 路线图，按 ROI 排序。
>
> 2026-09-23 更新：enterprise 试点 `targets/python-flask-enterprise/` 已建
> （DECISIONS.md D11/D12；确定性基线已冻结，joern 仅 13/25 链 CONFIRMED，
> LLM judge + agent 全量未跑——见 M14.3）。agent/LLM 层已知局限清单在
> `analysis/LIMITATIONS.md` §4：问题清单在 LIMITATIONS，排期在本文件，
> 两者交叉引用、不合并。
>
> 指导原则（2026-09-10 确立）：
> - 这是 AI SAST 项目：**LLM/agent 层优先**；引擎侧工作只有在能改变
>   verdict 或防正确性漂移时才做（D6、taint_confirm 的 D5/D7 数据流侧已
>   据此放弃，见 DECISIONS.md 与 PROGRESS.md "Remaining backlog"）。
> - 一切变更过 `run_baseline.py --compare` 门禁；不改 rules 评分作弊、不改
>   ground_truth、不动 targets 的红线不变（`docs/AGENT_MVP_PLAN.md` §9）。
> - LLM 接出的任何事实（链边、证据）必须带磁盘可解析 ref，过机械校验层。

## 排序总览

| 里程碑 | 主题 | 类型 | 预估 | ROI 理由 |
|---|---|---|---|---|
| M9 | LLM 断点续链机制化 | 效果 | ~3d | 直接决定新项目/反射/动态分派场景的检出率；M3 已验证过这个模式 |
| M10 | Semgrep 规则自进化 | 效果 | ~3d | 解决"新项目一开始检测不出、之后永远检测不出"的根因 |
| M11 | 知识库沉淀 + guard 前置 | 成本 | ~1.5d | verifier 是 token 大头（M4：2.5–4x；M7：9.4M），可复用知识最多 |
| M12 | 自我改进主循环 | 复利 | ~2.5d | benchmark 已到顶，收益体现在新 target / canary 上 |
| M13 | 防过拟合护栏 | 护栏 | ~1.5d | M12 的安全前提：没有它，hill-climbing 必然过拟合 4 个靶子 |

## M9 — LLM 断点续链机制化

背景：joern 前端对反射、动态分派、部分语言（C# 嵌套调用、JS require）
支持差。M3 已证明 agent 能从断点手动接力（js-sqli-02 / cs-cmdi-02 /
cs-path-traversal-01），但那是临场发挥；本里程碑把它做成结构化机制。
核心分工：**引擎负责过度近似地召回候选（便宜），LLM 负责语义消歧
（精确）**——同名碰撞对确定性算法是死结，对能读代码的 LLM 不是。

- **M9.0（前置）joern 脚本公共化**（~0.5d）：`backward_from_sinks.sc` /
  `extract_chain_snippets.sc` / `extract_entrypoint_snippets.sc` /
  `taint_confirm.sc` 四份复制了入口检测、sink 表、D5/D7 修补、
  `methodSource`、`esc/q`，且已漂移：`extract_chain_snippets.sc` 的 sink
  匹配用 ±1 窗口 + 简单 name 过滤，`backward_from_sinks.sc` 用 ±3 窗口 +
  三级 kind 排序——同一输入可能选出不同 sink 节点。抽公共 prelude。
  验收：4 target 确定性流水线输出（chains/taint JSONL）与合并前 diff
  为空，漂移消除。
- **M9.1 断点结构化输出**（~0.5d）：`backward_from_sinks.sc` 的
  `CHAINS_JSON` 每条链附 `dead_end` 对象（最后到达的方法 + 其体内未解析
  的调用表达式 + receiver 名/类型）；`pipeline.py` 的 InvestigationBrief
  带上断点现场，agent 不再重新推导断点位置。
- **M9.2 候选生成 + LLM 消歧**（~1d）：`joern_query` 新模板
  `find_call_sites(name)`——name-based 全图候选调用点（过度近似，即当年
  backlog 里否决的 name-based fallback，改为给 LLM 当候选生成器而非引擎
  判定器）；investigator prompt 新增消歧步骤：读 receiver 类型 / import
  绑定 / DI 注册处，选出正确接续边。
- **M9.3 反射/DI 专项 playbook**（~0.5d，纯 prompt）：DI 容器（链死在接口
  方法 → 搜实现类 → 读注册处确认接线 → 从实现继续）；反射（
  `Method.invoke` / `Class.forName` / `getattr` / `Activator.CreateInstance`
  ——追名字表达式，不追调用图）；JS/Python 动态分派（`obj[name]()`、
  回调注册、emitter）同法。
- **M9.4 接续边 provenance + 校验**（~0.5d）：chain 输出每跳标
  `engine | llm_inferred`（D7 LOW_CONFIDENCE 思路的结构化）；`report.py`
  校验层加规则：每个 llm_inferred 跳必须引用 justify 它的调用点行号
  （磁盘可解析 + 标识符出现在所引行内），否则降级。**这是防幻觉底线，
  没有它续链机制不上线。**
- 验收：4 target 全量回归 recall 不降、0 新 SAFE FP；在 workspace/ 下造
  一个反射/DI 驱动的 canary 场景（不动 targets）验证续链端到端打通。

## M10 — Semgrep 规则自进化

背景：规则是手写的 8 类 sink 形状匹配，新项目用了不认识的库/wrapper/写法
就永远漏检。进化单元不是"自由生成规则"，而是**分层知识库 + 机械生成器**，
出错面最小化。

- **M10.1 sink KB + 生成器**（~1d）：`analysis/rules/sink_kb.yml`，条目
  `{lang, library, api, vuln_type, pattern_hint, confidence:
  experimental|stable, origin}`；`scripts/kb_to_rules.py` 机械实例化为
  `sinks-*.yml`（生成物带 provenance 注释）。agent 进化时只提交 KB 条目。
- **M10.2 漏检信号检测器**（~0.5d，确定性零 LLM）：`pipeline.screen()`
  新阶段——`cpg.call` 危险名扫描（`(?i).*(query|exec|eval|render|parse|
  load|read|send).*`）减去现有规则覆盖 = 未覆盖清单；import 驱动（KB 已知
  危险库被 import 但代码里无标记命中）。补两个 LLM 侧信号：agent 观察工具
  `propose_sink(...)`（→ `workspace/agent-cache/<target>/sink_proposals.
  jsonl`）；"可疑沉默"检测（forward slice 有 DB/进程/文件操作但 0 sink）。
- **M10.3 沙盒晋升**（~1d）：候选永远先进 `workspace/rule-candidates/`。
  三关：① `semgrep --validate` + 动机代码必须命中；② 全 4 target 过
  `--compare` 门禁（无新 SAFE FP、recall 不降）；③ 噪声统计（每条候选规则
  维护 hits/confirmed/vetoed，连续全 veto 进隔离区）。experimental 规则的
  finding 置信度降一档，跑稳晋升 stable。
- 验收：在 workspace/ 造一个使用 KB 外库的场景，走完"信号 → 提议 → 候选
  → 门禁 → 入库"闭环，且 4 target 回归全绿。

## M11 — 知识库沉淀 + guard 前置（成本）

- **M11.1 路由 guard 链前置提取**（~0.5d）：`extract_entrypoint_snippets.sc`
  提取该路由实际经过的中间件/装饰器源码（Flask `before_request` / Express
  `app.use` 顺序 / Spring filter / ASP.NET middleware），一次提取、所有
  hypothesis 复用。省掉 M7 defender 每轮手工搜 middleware 的重复开销。
- **M11.2 sanitizer/guard 知识库**（~1d）：defender 轮次每轮都在重新发现
  同样的 sanitizer 知识（参数化查询、allow-list、硬化 XML 解析器），跑完
  即弃。按 `docs/why-not-agent-memory.md` §4 的结构化方案沉淀为 versioned
  JSON：条目带 evidence refs + 失效条件（enclosing function 变化即过期），
  以**显式上下文注入**喂给 investigator/verifier——不是隐式记忆。

## M12 — 自我改进主循环（复利）

- **M12.1 分层失败归因**（~0.5d）：聚合 chain_report / gap 分类 /
  verifier veto 率 / evidence violation 为 per-layer failure taxonomy
  （reason code 对齐 `why-not-agent-memory.md` §2 的 FP 来源表），
  postmortem 先机械归因再调 LLM。
- **M12.2 `run_improve.py` 闭环**（~1.5d）：批量跑 → 归因 → postmortem
  agent 提**一个**变更（变异空间 = 红线 §9.3 允许的 prompt/工具返回格式/
  预算）→ 应用 → 受影响 target 重跑 → 门禁 → 保留或回滚。prompt 全进
  git，每次变异记 mutation → score delta。
- **M12.3 变更 lint**（~0.5d）：改进循环产出的 diff 禁止出现 target 特定
  字符串（路由名、函数名），强制变异必须是通用模式。
- 验收：人工埋一个已知 FN，闭环能定位、修复、过门禁，且不引入新 FP。

## M13 — 防过拟合护栏

- **M13.1 canary 变异测试**（~1d）：`workspace/` 下生成 targets 的变异
  副本（换变量名、换 wrapper 层级、换框架写法）测召回率——这是泛化能力
  的适应度函数，ground truth 只当及格线。M12 的变异必须在 canary 上
  不退化才算保留。
- **M13.2 模型漂移监控**（~0.5d）：定期 judge-only 对比
  （`--from-verdicts` vs 新鲜调用），门禁报告区分"模型漂移"与"代码
  变更"，重钉基线走显式 changelog（M0 已被 DeepSeek 漂移咬过两次）。

## M14 候选（2026-09-23 架构讨论，未排期）

来源：漏斗架构复盘（Semgrep 普查 → joern 分级 → LLM 判定 → agent 下钻 →
对抗复核）。原则：早期阶段只分级、不过滤（joern UNCONFIRMED ≠ 安全，
只降优先级不丢弃）；LLM 用量与不确定性挂钩，不与代码量挂钩。

- **M14.1 统一编排器**：`run_agent.py` / `run_planner.py` / `run_worker.py`
  三个 CLI 收进一个 orchestrator，产出一份分阶段漏斗报告（每层的
  输入/输出/降级原因/tokens 分段统计）——现在是割裂的三份。
- **M14.2 批量判定三态化 + 模型分层**：batch judge 输出
  likely-TP / likely-FP / uncertain 三态，只有 uncertain 升级 agent
  下钻（likely-TP 仍过对抗复核；likely-FP 保守处理——拿不准降置信度，
  不直接丢弃）；批量初判用便宜模型，下钻/复核才用强模型。对应
  LIMITATIONS §4 的成本条目——目前最大的成本杠杆。
- **M14.3 enterprise 全量验证**：LLM judge + agent 全量跑
  `targets/python-flask-enterprise`（joern 确认率仅 52%，下钻负载目前
  是外推不是实测；LIMITATIONS §4）。这是 M14.1/M14.2 的首个真实
  验证场。

## 依赖关系

- M9.0 是 M9.1–9.4 的前置；M9 与 M10 互相独立，可并行。
- M12 依赖 M13.1（没有 canary 护栏的改进循环会过拟合，不如不做）。
- M11 独立，任何时候插进来都只有收益。

## 未排期（自 `docs/AGENT_MVP_PLAN.md` §10 并入，2026-09-23）

- 生产无 ground truth 运营：置信度分级 + 人工分诊反馈回流 + canary 注入
  测召回；确认的野外漏洞镜像回 benchmark（targets 维护流程见 AGENTS.md）。
- CPG 构建队列化与增量缓存（平台化）。
- 跨扫描记忆层：已否决——`docs/why-not-agent-memory.md`；M11.2 的结构化
  知识库是替代方案。

## 不做清单（已决策，勿复活）

- D6（write-site snippets）、taint_confirm 的 D5/D7 数据流侧——LLM 已
  覆盖到 recall 天花板，机械版不改任何 verdict（DECISIONS.md 2026-09-10）。
- CFG-dominance 检查、forward dataflow 发现 sink、新 source 种类——
  DECISIONS.md "Decided against / deferred"。
- agent 自由记忆——`docs/why-not-agent-memory.md`；用 M11.2 的结构化
  知识库替代。
