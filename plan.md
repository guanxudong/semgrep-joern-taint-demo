# AI SAST agent 产品化路线图（post-MVP）

> 2026-09-10 制定。M0–M8 已全部关闭（原规格与执行记录随 investigator
> 路径于 2026-11-01 一并退役，见 DECISIONS.md D19；历史可在 git 查到），
> benchmark 在天花板：A 类 recall 全满（2026-11-07 ground truth 重审补记
> 8 条 sqli 后为 10/10–12/12 视 target），SAFE FP 仅基线自带。
> 当前架构只针对 A 类（sink-based）；B 类检测后续另行立项。
> 本计划是 post-MVP 路线图，按 ROI 排序。
>
> 2026-10 更新：enterprise 试点 `targets/python-flask-enterprise/` 已由用户
> 删除（确定性基线曾冻结：joern 仅 13/25 链 CONFIRMED，LLM 层未实测——
> 验证场重定见 M14.3）。agent/LLM 层已知局限清单在
> `analysis/LIMITATIONS.md` §4：问题清单在 LIMITATIONS，排期在本文件，
> 两者交叉引用、不合并。
>
> 2026-09-23 重排（用户决定）：主线转为 **AI SAST
> agent 产品化**——M14 由候选转正为 Phase 1（顺序 M14.1 → M14.3 →
> M14.2 → M11；M9 已于 2026-11-01 以 tracer 状态机交付）；自进化类
> （规则自我更新 M10、改进主循环 M12、canary 护栏 M13.1）整体推后为
> Phase 2，等 M14.3 产出真实失败归因后再评估启动。
>
> 指导原则（2026-09-10 确立）：
> - 这是 AI SAST 项目：**LLM/agent 层优先**；引擎侧工作只有在能改变
>   verdict 或防正确性漂移时才做（D6、taint_confirm 的 D5/D7 数据流侧已
>   据此放弃，见 DECISIONS.md 与 PROGRESS.md "Remaining backlog"）。
> - 一切变更过 `run_baseline.py --compare` 门禁；不改 rules 评分作弊、不改
>   ground_truth、不动 targets 的红线不变（AGENTS.md "Core constraints" +
>   "Changing the targets"）。
> - LLM 接出的任何事实（链边、证据）必须带磁盘可解析 ref，过机械校验层。

## 排序总览（2026-09-23 重排：AI SAST agent 产品化为主线）

主线：把现有 pipeline 整合成可在真实仓库一键运行的 AI SAST agent——
统一编排 → 实测验证 → 成本可控 → 按实测补效果。自进化类推后（见
Phase 2）：benchmark 已到顶，先把"能跑、量得准、跑得起"做完。

### Phase 1 — agent 产品化主线

| 顺位 | 里程碑 | 主题 | 预估 | 理由 |
|---|---|---|---|---|
| 1 | M14.1 | 统一编排器 + 分阶段漏斗报告 | ~1.5d | 产品骨架；漏斗报告是解读一切验证结果的仪器 |
| 2 | M14.3 | 真实形态代码全量验证 | ~1d + token 预算 | 无过拟合验证场；产出 M14.2 的成本画像（验证场待重定，见 M14.3 正文） |
| 3 | M14.2 | 批量判定三态化 + 模型分层 | ~2d | 最大成本杠杆；真实代码量级的反复回归跑得起来的前提 |
| 4 | ~~M9~~ ✅ 2026-11-01 | LLM 断点续链机制化（以 tracer 状态机落地） | ~3d → 已交付 | 效果项；按 M14.3 实测失败清单做，不凭小靶子猜 |
| 5 | M11 | 知识库沉淀 + guard 前置 | ~1.5d | 成本项；独立，任何时候插入都是收益 |

M13.2（模型漂移监控，~0.5d）不推后也不单独立项：随 baseline 重钉需求
插入，临近生产运营时必做（模型漂移已咬过两次）。

### Phase 2 — 推后（自进化类，启动条件见"依赖关系"）

| 里程碑 | 主题 | 推后理由 |
|---|---|---|
| M10 | Semgrep 规则自进化 | 需要 M14.3 的真实漏检信号；小靶子上无漏可补 |
| M12 | 自我改进主循环 | 没有真实失败归因时 hill-climbing 只会过拟合小靶子 |
| M13.1 | canary 变异测试 | M12 的护栏，随 M12 一起走 |

## M10 — Semgrep 规则自进化（⏸ 推后，Phase 2）

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
  三关：① `semgrep --validate` + 动机代码必须命中；② 全 3 个 web 目标过
  `--compare` 门禁（无新 SAFE FP、recall 不降）；③ 噪声统计（每条候选规则
  维护 hits/confirmed/vetoed，连续全 veto 进隔离区）。experimental 规则的
  finding 置信度降一档，跑稳晋升 stable。
- 验收：在 workspace/ 造一个使用 KB 外库的场景，走完"信号 → 提议 → 候选
  → 门禁 → 入库"闭环，且全 target 回归全绿。

## M11 — 知识库沉淀 + sanitizer 复用（成本）

- **M11.2 sanitizer/guard 知识库**（~1d）：defender 轮次每轮都在重新发现
  同样的 sanitizer 知识（参数化查询、allow-list、硬化 XML 解析器），跑完
  即弃。按 `docs/why-not-agent-memory.md` §4 的结构化方案沉淀为 versioned
  JSON：条目带 evidence refs + 失效条件（enclosing function 变化即过期），
  以**显式上下文注入**喂给 tracer/verifier——不是隐式记忆。

  （原 M11.1 路由 guard 链前置提取依赖 entrypoint 正向切片脚本，随 B 类
  检测一并移出当前架构；若未来恢复 B 类可重提。）

## M12 — 自我改进主循环（复利）（⏸ 推后，Phase 2）

- **M12.1 分层失败归因**（~0.5d）：聚合 chain_report / gap 分类 /
  verifier veto 率 / evidence violation 为 per-layer failure taxonomy
  （reason code 对齐 `why-not-agent-memory.md` §2 的 FP 来源表），
  postmortem 先机械归因再调 LLM。
- **M12.2 `run_improve.py` 闭环**（~1.5d）：批量跑 → 归因 → postmortem
  agent 提**一个**变更（变异空间 = 红线允许的 prompt/工具返回格式/
  预算）→ 应用 → 受影响 target 重跑 → 门禁 → 保留或回滚。prompt 全进
  git，每次变异记 mutation → score delta。
- **M12.3 变更 lint**（~0.5d）：改进循环产出的 diff 禁止出现 target 特定
  字符串（路由名、函数名），强制变异必须是通用模式。
- 验收：人工埋一个已知 FN，闭环能定位、修复、过门禁，且不引入新 FP。

## M13 — 防过拟合护栏（⏸ M13.1 推后，Phase 2；M13.2 见排序总览）

- **M13.1 canary 变异测试**（~1d）：`workspace/` 下生成 targets 的变异
  副本（换变量名、换 wrapper 层级、换框架写法）测召回率——这是泛化能力
  的适应度函数，ground truth 只当及格线。M12 的变异必须在 canary 上
  不退化才算保留。
- **M13.2 模型漂移监控**（~0.5d）：定期 judge-only 对比
  （`--from-verdicts` vs 新鲜调用），门禁报告区分"模型漂移"与"代码
  变更"，重钉基线走显式 changelog（M0 已被 DeepSeek 漂移咬过两次）。

## M14 — agent 产品化主线（2026-09-23 由候选转正，Phase 1）

来源：漏斗架构复盘（Semgrep 普查 → joern 分级 → LLM 判定 → agent 下钻 →
对抗复核）。原则：早期阶段只分级、不过滤（joern UNCONFIRMED ≠ 安全，
只降优先级不丢弃）；LLM 用量与不确定性挂钩，不与代码量挂钩。
执行顺序：M14.1 → M14.3 → M14.2。

- **M14.1 统一编排器**（~1.5d）：`run_trace.py` / `run_baseline.py`
  收进一个 orchestrator，产出一份分阶段漏斗报告（每层的输入/输出/
  降级原因/tokens 分段统计）。验收：`uv run agent/run.py --target
  <name>` 一条命令跑完 A 类全程，漏斗报告落盘，全 target 回归门禁
  PASS。
- **M14.3 真实形态代码全量验证**（~1d + token 预算）：LLM judge + agent
  全量跑一个分层/真实形态的验证场，实测下钻负载（目前是外推不是实测；
  LIMITATIONS §4）。**验证场待重定**：原 enterprise 试点
  `targets/python-flask-enterprise` 已于 2026-10 由用户删除（git 历史
  可恢复）；候选是 engine-backed 的 `java-fix-gateway`（非 HTTP、registry
  分派，可顺带打通非 HTTP 目标的流水线接线）或重建一个分层 web 试点。
  验收：产出分层失败归因报告（recall/FP/每层 token 分布），M14.2 的
  成本画像从这份报告导出。
- **M14.2 批量判定三态化 + 模型分层**（~2d）：batch judge 输出
  likely-TP / likely-FP / uncertain 三态，只有 uncertain 升级 agent
  下钻（likely-TP 仍过对抗复核；likely-FP 保守处理——拿不准降置信度，
  不直接丢弃）；批量初判用便宜模型，下钻/复核才用强模型。对应
  LIMITATIONS §4 的成本条目——目前最大的成本杠杆。验收：同等 recall
  下验证场全量 token 消耗显著下降（基线 = M14.3 实测值），
  全 target 回归门禁 PASS、0 新 SAFE FP。**成本护栏已就位（D16）**：
  `run_baseline.py --compare … --max-token-delta 30` 会把
  "recall 不降但 token 暴涨" 变成一次 FAIL，成本基线取上一次同形态
  batch（judge 基线每链一次调用，与 agent 每次下钻不可比）。

## 依赖关系

- 主线顺序 M14.1 → M14.3 → M14.2：M14.1 的漏斗报告让 M14.3 的
  结果可按阶段解读；M14.3 的失败归因喂给 M14.2（成本画像）。token
  预算紧张时 M14.2 可与 M14.3 对调——先控成本再全量跑。
- M9（断点续链）已于 2026-11-01 交付，不再阻塞任何里程碑。
- M11 独立，任何时候插进来都只有收益。
- Phase 2 启动条件：M10 需要 M14.3 的真实漏检信号；M12 依赖 M13.1
  （没有 canary 护栏的改进循环会过拟合，不如不做），两者都以 M14.3 的
  失败归因为前提。推后是顺序安排，不是不做。

## 未排期（原 MVP 规格遗留项并入，2026-09-23）

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
