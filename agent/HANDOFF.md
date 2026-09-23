# Agent MVP 进度交接（2026-09-05，M8 完成）

> 给新会话的接续说明。实现规格见 `docs/AGENT_MVP_PLAN.md`（M0–M8 已全部
> 关闭，历史文档）。本文件记录执行状态；后续路线图见根目录 `plan.md`。

> **⚠️ jsp-legacy 已于 2026-09-05 从仓库删除**（用户决定，不想覆盖老技术）。
> `targets/jsp-legacy/` 与 `scripts/jsp_to_java.py` 已 `git rm`（git 历史可
> 恢复）。`config.TARGETS` / `run_baseline.py` 的 jsp 条目已移除。本文档
> 历史表格（M0 基线、M3–M6 数字）里的 jsp 行均为历史记录，不再有效。
> 残留（无害、休眠）：`sinks-java.yml` 的 `out.print` 模式、joern 脚本的
> `_jspService` 检测、评分器的 `_jsp.java→.jsp` 归一化；workspace 下的
> jsp 缓存（`workspace/jsp-java`、`agent-cache/jsp-legacy`、baseline/reports
> 里的 jsp 条目）可手动删除。

## 总体状态

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 基线固化 | ✅ 完成 | `agent/run_baseline.py`，结果在 `workspace/baseline/` |
| M1 工具层 | ✅ 完成 | `agent/sast_agent/{config,contracts,pipeline,tools}.py` + smoke 全绿 |
| M2 调查 agent + 报告 | ✅ 完成 | python-flask A 10/10、0 FP |
| M3 动态下钻 | ✅ 完成 | 5 target 全量回归全绿，三个靶子全部达标（见下） |
| M4 对抗复核 + 置信度分级 | ✅ 完成 | `verifier.py` + `report.apply_verifier()`，验收 9/9，回归全绿（见下） |
| M5 批量化 + 回归门禁 | ✅ 完成 | `run_agent.py --target all`（并行 2）+ `run_baseline.py --compare`，验收见下 |
| M6 B 类 planner | ✅ 完成 | `agent/run_planner.py` + `sast_agent/planner.py`，5 target B 路由覆盖 45/45（见下） |
| M7 B 类 worker | ✅ 完成 | `worker.py` + `run_worker.py`；验收 4/4 target PASS（jsp-legacy 当时按用户决定排除，后于 2026-09-05 删除，见下） |
| M8 taxonomy 检查表 + B 类门禁 | ✅ 完成 | planner 逐类审计表入 report_b.md；`run_baseline.py --compare` 自动识别 summary_b.json（见下） |

## M8 实现要点（2026-09-05，计划 §7A 完整性约束 / §8-M8）

- **taxonomy 覆盖检查表**：`contracts.TaxonomyEntry`（vuln_type 限 7 类 +
  routes_examined/submitted/excluded[{route, reason}]）。planner 的
  `submit_hypotheses` 工具增加必填 `coverage` 参数（一次调用原子提交，
  避免第二个工具被遗忘）；prompt 要求 7 类逐类记账（考察几条、提交哪些、
  排除哪些+理由），缺席有效性判断仍是 worker 的活。
  `tools._validate_coverage` 宽容兜底：整体校验失败或缺类时从队列机械补全
  （routes_examined=0 表示"planner 未报告"），JSON 里标 `"derived": true`；
  检查表落 `workspace/agent-cache/<target>/taxonomy_checklist.json`
  （planner 重跑先清旧的，防止陈旧检查表残留）。
- **入报告**：`report.render_markdown_b(..., checklist=None)` 尾部新增
  `## Taxonomy coverage audit` 表（类 | examined | submitted | excluded
  (route — reason)）；`run_worker.finalize_target_b` 从 cache 读检查表传入。
  无检查表时渲染 "not available (pre-M8 queue)" 提示。
- **B 类回归门禁**：`run_baseline.py --compare` 按内容自动识别
  `summary.json`（A 类，对 judge_a）vs `summary_b.json`（B 类，对
  judge_b）：recall 命中数低于基线即 FAIL；新 SAFE FP（不在基线
  judge_a/judge_b safe_fp 并集，即容忍 py/java/js/cs-safe-02）即 FAIL。
  `_latest_summary()` 改为 glob `*/summary*.json`（两种汇总都找）。
- **验收（2026-09-05）**：`agent/smoke_m8.py` 25 项无 LLM 检查全过
  （契约接受/拒绝、coverage round-trip、partial/invalid 兜底、渲染、
  门禁伪造用例 PASS/recall 降/新 FP/A 类回归）；`run_worker.py --target
  all --dry-run` 全通；4 target planner 重跑全部 7 类齐、无 derived 兜底、
  GT 路由覆盖 9/9（M6 gate PASS），tokens py 75.6k / java 68.0k / js 96.4k
  / cs 60.2k ≈ 300k；用 M7 验收真实 `summary_b.json`
  （`workspace/agent-reports/2026-09-04-233106-m7/`）跑门禁端到端
  **GATE: PASS**（4/4，FP 恰为基线已知四个）。M8 两项验收（检查表入
  报告 + B 类门禁）达成，AGENT_MVP_PLAN.md 里程碑全部关闭。

## M7 实现要点（2026-09-04，计划 §7A）

- **`sast_agent/worker.py`**：克隆 investigator.py 骨架。每 hypothesis 一个
  agent run；工具 = `get_forward_slice` + **剥 GT 标记的** read_function /
  search_code 包装（A 类 read_function 不剥是 M3 已知泄漏面，worker 侧全剥）
  + `submit_b_finding`，不挂 joern_query。prompt = 缺席对比 playbook 4 步
  （slice → 找应有检查 → search 同类惯用法 → 对比定案）+ 7 类 should-be-check
  提示表 + middleware/框架层 guard 指引（Flask before_request / Express
  app.use / Spring filter / ASP.NET middleware / web.xml）。预算
  `WORKER_MAX_TOOL_CALLS=15` / `WORKER_TIMEOUT_SECONDS=600`，剩 2 次注入
  "submit now"。提交从 message history 的 ToolCallPart 反向扫描提取
  （DeepSeek thinking 端点拒 output_type 的 tool_choice，同 M2/M4 教训）；
  超时/预算兜底合成 honest not-vulnerable/0.1 BFinding。
- **契约/工具**：`contracts.BFinding`（hypothesis 原样回填 +
  verdict/confidence_level/evidence/exploit_sketch/sanitizer_notes/
  comparison/stats），`Evidence.kind` 增 `"absence_comparison"`；
  `tools.submit_b_finding` 校验后追加 `cache_dir/findings_b.jsonl`
  （与 submit_finding 同模式；最终落盘由 run_worker 负责）。
- **置信度映射（机械，plan §4）**：`report.assign_confidence_level_b` ——
  vuln ∧ absence_comparison evidence refs ≥2 可解析 → CONFIRMED，否则
  LIKELY；not-vulnerable → SUSPICIOUS（同 A 类惯例）。verifier 合并
  `report.apply_verifier_b` 复用 apply_verifier 的 dict surgery（defender
  veto 仍需 ≥1 ref 磁盘可解析）；`apply_validation(b_class=True)` 加规则：
  CONFIRMED B 无 absence_comparison evidence → 降 LIKELY。
- **verifier B 轮**：`verify_b_finding` 复用 `_run_one`/`_extract_report`/
  submit_report 机制与预算；attacker 构造具体越权请求（"as user 1,
  GET /users/2"），defender 专搜 middleware/框架层统一挂载的 guard。
- **评分**：`report.score_b_findings` 镜像 `llm_judge_entrypoints.py`
  （file+function 主匹配 strength 1000，file+route 后缀回退，每 gt 条目
  只取最高 strength；同 vuln_type 且 vuln → TP；SAFE B 样本同型命中 → FP）。
  hypothesis.entrypoint（"file:function"）经 `_hypothesis_as_record` 适配成
  judge 的 entrypoint-record 形状；`_jsp.java → .jsp` 归一沿用 cpg_file。
- **CLI `run_worker.py`**：`uv run --offline agent/run_worker.py --target
  <name|all> [--limit N] [--no-verify] [--dry-run]`。读
  `workspace/agent-cache/<target>/hypotheses.jsonl`（缺失即报错提示先跑
  run_planner.py）。逐 hypothesis 调查 → vulnerable 且非 --no-verify 接
  verifier → 追加写报告目录 `findings_b.jsonl`；尾段
  `finalize_target_b`：apply_validation → score（ground_truth 仅此处读）→
  `report_b.md`。输出落 **`workspace/agent-reports/<date>-m7/<target>/`**
  （与 A 类 `<date>/` 目录隔离），all 模式顺序跑 + 聚合 `summary_b.json`。
  `--dry-run` 零 LLM：stub finding 打通队列加载→校验→评分→渲染全链路。
- **已验证（无 LLM）**：py_compile 全过；import/单元 smoke（BFinding
  round-trip、置信度映射、prompt 无残留 .format 占位符、submit_b_finding
  接受/拒绝、scorer 真实 finding TP + 类型不符 FN、validation B 规则降级、
  verifier veto（可解析 ref）与幻觉 veto（忽略））；`--target all --dry-run`
  5 target 全通，每 gt B 条目均被 ≥1 hypothesis 匹配，summary_b.json 落盘。
- **修复过的三个问题（2026-09-04，验收跑前）**：
  1. **GT 标记泄漏（红线 §9.2）**：`_strip_gt_tags` 旧 regex 是 `^` 锚定
     （`^\s*(?://|#)...`），只剥得了原始 snippet 代码——`read_function`
     输出带行号前缀（`"   9: # VULN: ..."`）、`search_code` 输出是 rg 格式
     （`path:9:# VULN: ...`），两者都漏剥。首轮验收跑 python-flask 的
     finding reasoning 直接引用了 VULN 标签当证据 → 整轮作废。已改为
     `(?://|#)\s*(?:VULN|SAFE):[^\n]*`（行内任意位置剥掉标签段，保留
     行号/路径前缀），investigator.py 与 tools.py 两处同步；A 类 verifier
     的 read/search 包装共用此函数，同一漏洞一并堵上。冒烟验证三种格式
     均剥净。**注意：A 类 M3/M4 回归是在这个洞存在时跑出的（verifier 侧），
     且 investigator 的 read_function 本来就不剥（已知泄漏面，保持原样）。**
  2. **token 预算耗尽**：python-flask 17 条 hypothesis 烧了 1.99M，撞
     MAX_TOTAL_LLM_TOKENS=2M 上限导致第 16 条 0 调用 budget_exhausted。
     B 类独立预算 `WORKER_TOTAL_LLM_TOKENS=3_000_000`（config.py），
     run_worker 改用它。
  3. **瞬时 API 错误无重试**：java 一条 hypothesis 遇 Connection error
     直接合成 not-vulnerable 假 FN。worker 现在对一般异常也重试一次
     （与 timeout 同待遇）。
- **假设级并行**：`run_worker.run_target` 改为 semaphore 限流的
  `asyncio.gather`（`WORKER_CONCURRENCY=3`，config.py；峰值并发 LLM
  调用 ≈ 3×(worker+2 verifier 轮) = 9）。并行前**顺序预热**
  `pipeline.get_entrypoint_snippets(target)`（冷 joern 子进程会阻塞事件
  循环）。findings_b.jsonl 仍逐条完成即追加（崩溃安全），评分不依赖顺序。
- **首轮（作废）数据点**：py 7/7、0 FP、每条 CONFIRMED 都有像样的
  absence_comparison 证据——但因泄漏面作废，仅说明 playbook 形态正确。
  作废跑报告：`workspace/agent-reports/2026-09-04-080349-m7/`（py 完整、
  java 部分）。
- **验收结果（2026-09-04 23:31 起跑，`workspace/agent-reports/2026-09-04-233106-m7/`）**：
  **PASS，4/4 target**——recall_B py/java/js 7/7（≥ 基线 7/7）、cs 7/7
  （**高于**冻结基线 6/7）；SAFE FP 恰好是基线自带的 py/java/js/cs-safe-02
  四个，**0 新增**；48 条 CONFIRMED 全部带 absence_comparison evidence，
  190 个 file:line refs 抽查全部真实存在于磁盘；finding 文本 0 GT 标签
  泄漏。墙钟 ~27 分钟（并发 3），总 tokens ~9.4M。**jsp-legacy 按用户决定
  排除**（跑到 jsp 前被叫停；2026-09-05 起该项目已从仓库删除，见顶部
  说明）。run_worker.py 新增 `--exclude` 支持选择性
  批量。M7 三项验收标准（§7A-M7）在满足"4 target"口径下全部达成。

## M6 实现要点（2026-09-03，计划 §7A / §8-M6）

- **`sast_agent/planner.py`**：每 target 一个 planner run。`_build_digest()`
  从缓存的 repo_map.json 构建路由表 + 符号摘要（jsp 按 D9 约定从
  `pages/X_jsp.java` 合成伪路由 `JSP /X.jsp`）；agent 挂
  `submit_hypotheses` / `search_code` / `read_function` 三个工具，
  预算 `PLANNER_MAX_TOOL_CALLS=15` / `PLANNER_TIMEOUT_SECONDS=600`。
- **新工具（tools.py）**：`submit_hypotheses`（逐条按 `Hypothesis` 契约校验，
  vuln_type 限 7 类 B 类，宽容入队，追加写 `cache_dir/hypotheses.jsonl`）；
  `get_forward_slice(entrypoint)`（封装 `extract_entrypoint_snippets.sc` 经
  `pipeline.get_entrypoint_snippets()` 缓存到 `entrypoint_snippets.jsonl`，
  method/route/函数名三级匹配，返回前剥 VULN:/SAFE: 标记）。M7 worker 的
  playbook 第 1 步工具已就绪。
- **`agent/run_planner.py`**：`uv run --offline agent/run_planner.py --target
  <name|all>`（all 为顺序跑）。跑完默认做覆盖率校验（`--no-check` 关）：
  读 ground_truth.json（仅校验器可见）逐条 B 类条目按 route 后缀匹配 +
  占位符归一；`JSP`/`ANY` 动词视为通配（脚本 JSP 页不限动词）；容忍
  "GET /x -> Handler:13" 形式的标签。非 100% 覆盖退出码 1。
- **prompt 关键**：启发式表必须写成**强制映射**（"匹配即必须提交，guard 可见
  也要提交、记进 rationale"）——写成普通启发式时模型会自己核实代码、看到
  guard 就丢假设，safe-02/05 路由全丢（缺席有效性判断是 M7 的活，planner
  只负责不漏）。
- 验收（2026-09-03）：5 target 顺序跑，B 类路由覆盖 **45/45**（含每 target
  2 条 safe B 样本路由），M6 gate: PASS。假设数 16/14/16/16/18，总 ~272k
  tokens，墙钟 ~6.4 分钟。假设落盘 `workspace/agent-cache/<target>/
  hypotheses.jsonl`（M7 worker 的输入队列）。

## M5 实现要点（2026-08-15）

- **`run_agent.py --target all`**：ThreadPoolExecutor 并行 2（每 target
  一个独立 asyncio 事件循环跑在自己的线程里；joern 内存限制，别开多）。
  报告落 `workspace/agent-reports/<date>/<target>/`，聚合
  `workspace/agent-reports/<date>/summary.json`（每 target 的
  recall/FP/TP-FN-FP-TN/tokens/report 路径）。当天已有 summary.json 时
  自动加 `-HHMMSS` 后缀，不覆盖。单 target 模式输出目录不变
  （`workspace/agent-reports/<target>/`，smoke_verifier 依赖它）。
  某 target 失败不影响其它 target，记进 summary 并令退出码非零。
  原 main() 尾段（校验 → 评分 → report.md）抽成 `finalize_target()`
  供两种模式复用。
- **`run_baseline.py --compare [summary.json]`**（默认取
  `workspace/agent-reports/` 下最新 summary.json）：对照冻结基线
  `workspace/baseline/baseline.json`。门禁规则（计划 §8-M5）：
  A 类 recall 命中数低于基线 judge_a → FAIL；出现**新** SAFE FP
  （不在基线 judge_a/judge_b safe_fp 并集里，即 py-safe-02 等已知 FP
  容忍）→ FAIL；target 运行出错或无基线 → FAIL。summary 里缺的
  target 只报告 skipped 不判失败（支持部分门禁）。非零退出 = 回归。
- 验证：`--compare` 三条伪造用例（PASS / recall 降 / 新 FP）行为正确；
  `--target all --limit 1 --no-verify` 冒烟 5 target 全跑通、并行 2
  生效、summary.json 落盘，`--compare` 默认路径正确 FAIL（limit 1
  的必然结果，顺带端到端验证了门禁）。全量验收回归见下表。

## M5 全量验收回归（2026-08-15，`--target all` 并行 2 + verifier 开）

| target | A recall | SAFE FP | tokens | findings 置信度分布 |
|---|---|---|---|---|
| python-flask | 10/10 | 0 | 645k | 9 CONFIRMED / 2 LIKELY / 2 SUSPICIOUS |
| java-spring | 10/10 | 0 | 636k | 9 / 1 / 1 |
| js-ts-express | 10/10 | 0 | 718k | 11 / 2 / 4 |
| csharp-aspnet | 10/10 | 0 | 774k | 6 / 4 / 5 |
| jsp-legacy | 10/10 | 0 | 850k | 12 / 0 / 4 |

- 报告：`workspace/agent-reports/2026-08-15-090219/`（同日已有冒烟的
  `2026-08-15/`，自动加了 `-HHMMSS` 后缀）。
- `python3 agent/run_baseline.py --compare` → **GATE: PASS**（5/5，
  java/jsp 的 agent recall 高于基线 judge_a 也算 PASS）。
- **墙钟 ~32 分钟**（M4 顺序 105 分钟；并行 2 + 全缓存）。总 LLM
  tokens ~3.62M，与 M4 顺序运行（~3.78M）持平。
- M5 验收标准（计划 §8-M5：一键全量跑通 + 报告落盘
  `workspace/agent-reports/<date>/` + 门禁非零退出语义）全部满足。

## M4 最终结果（2026-08-12 全量回归，verifier 默认开启）

| target | A recall | SAFE FP | tokens（M3 对比） | findings 置信度分布 |
|---|---|---|---|---|
| python-flask | 10/10 | 0 | 603k（171k） | 9 CONFIRMED / 2 LIKELY / 2 SUSPICIOUS |
| java-spring | 10/10 | 0 | 597k（149k） | 8 / 2 / 1 |
| js-ts-express | 10/10 | 0 | 755k（251k） | 11 / 2 / 4 |
| csharp-aspnet | 10/10 | 0 | 858k（363k） | 6 / 4 / 5 |
| jsp-legacy | 10/10 | 0 | 969k（348k） | 11 / 1 / 4 |

- 真实运行零误伤：5 target 共 2.4M verifier tokens，**0 误 veto、0 attacker
  降级、0 失败轮次**；三个 M3 下钻靶子（js-sqli-02 / cs-cmdi-02 /
  cs-path-traversal-01）仍 vuln=True LIKELY 0.95+、证据零 violation。
- **M4 验收 smoke**（`uv run --offline agent/smoke_verifier.py --target all`）：
  把每个有 finding 的 SAFE A 类样本强制改成 vulnerable/CONFIRMED（模拟
  investigator 犯错），跑真实 attacker/defender 轮次后 defender
  **9/9 全部 veto 回 not-vulnerable**（正确识别参数化查询、allow-list、
  XXE 硬化解析器）。3 个样本按 primary-chain 规则跳过（sink 被真漏洞链
  共享，finding 判定对象不是安全样本），2 个样本 sink 上无 finding。
- 5 target 顺序全跑约 105 分钟（joern 全缓存时；M3 约 40 分钟，verifier
  每 vuln sink 多两轮 LLM）。

## M4 实现要点

- `verifier.py`：attacker（构造具体触发请求）/ defender（找有效 sanitizer，
  必须给 file:line refs）两轮独立 agent，只看 evidence 包不看
  investigator 推理过程；工具只有 read_function/search_code（无
  joern_query，§7），输出剥 VULN:/SAFE: 注释。预算
  `VERIFIER_MAX_TOOL_CALLS=10`、`VERIFIER_TIMEOUT_SECONDS=300`（config.py）。
- **报告走 submit_report 工具提交，不用 output_type**：DeepSeek
  thinking 端点对 output_type 的 tool_choice 直接 400（"Thinking mode
  does not support this tool_choice"）——和 investigator 用
  submit_finding 是同一个原因。从 message history 的 ToolCallPart 提取。
- `report.apply_verifier(finding, vres, tree)`（机械合并，§4）：
  - defender veto 条件：`effective_sanitizer=true` **且至少一条 ref 在
    磁盘上可解析**（防幻觉 sanitizer 误杀真漏洞）；满足则翻转
    is_vulnerable=False、降 SUSPICIOUS、reasoning 追加 veto 说明；
  - attacker `exploit_possible=false` → 降一级（CONFIRMED→LIKELY→
    SUSPICIOUS），不影响 is_vulnerable（不影响 recall）；
  - 失败轮次（None：超时/配额/400）一律无效化，不改变判定；
  - 空 exploit_sketch/sanitizer_notes 用 verifier 结果补齐（§9.4）。
- `run_agent.py`：vulnerable finding 自动接 verifier，`--no-verify` 可关；
  每 sink 日志追加 verifier 状态。token 预算与 investigator 共享
  MAX_TOTAL_LLM_TOKENS 余额。
- report.md 头部新增置信度分布行，每条 finding 有 Verifier 行
  （exploit/sanitizer/veto/notes）。
- `smoke_verifier.py`：M4 验收脚本。匹配 safe 样本时用与评分一致的
  **primary-chain 规则**（教训：非 primary 匹配会把"判定对象是真漏洞链"
  的 finding 错当成 safe 样本的 finding 去强制，attacker 会正确地从真
  漏洞链构造出 exploit —— 那是 harness 的假象，不是 verifier 漏拦）。

## M3 最终结果（2026-08-12 全量回归）

| target | A recall（冻结基线） | SAFE FP | tokens | findings/report |
|---|---|---|---|---|
| python-flask | 10/10（10/10） | 0（基线 B 类 py-safe-02） | 171k | 成对 |
| java-spring | 10/10（8/10） | 0（基线 B 类 java-safe-02） | 149k | 成对 |
| js-ts-express | 10/10（10/10） | 0（基线 B 类 js-safe-02） | 251k | 成对 |
| csharp-aspnet | 10/10（10/10） | 0（基线 B 类 cs-safe-02） | 363k | 成对 |
| jsp-legacy | 10/10（9/10） | 0（基线 B 类 jsp-safe-05） | 348k | 成对 |

三个靶子（计划 §6A，全部 vuln=True、证据零 violation）：
- `js-sqli-02`（services/userService.js:14，GAP_FLOW_DEAD）：LIKELY 0.95，
  agent 自行补出 `req.query.name → stageName → pendingName → findStaged →
  db.query`（refs: routes/users.js:17-22, userService.js:5-9/12-15,
  db/index.js:12-18）；
- `cs-cmdi-02`（Services/ToolService.cs:19，GAP_FLOW_DEAD）：LIKELY 0.95，
  `_target` 字段跨方法接力（StageTarget 写入 → RunStagedDiag 读取）补齐；
- `cs-path-traversal-01`（Services/FileService.cs:16，GAP_FLOW_DEAD）：
  LIKELY 0.95，Download → ReadUserFile → Path.Combine 链路补齐。

## M3 修过的问题（全部只改 agent 侧，红线未碰）

1. **超时假 FN**（cs 6/10 的根因）：`SINK_TIMEOUT_SECONDS` 180 → **600**
   （config.py）。180s 在 DeepSeek 慢时两次重试都超时，investigator 合成
   confidence 0.1 的 not-vulnerable 兜底 finding。修后同 sink 25-37s 完成。
2. **校验层误伤**（report.py，反伪造骨架保留）：
   - ref 解析从全匹配改为**提取式**（容忍 `file:11-22 (entrypoint ...)`
     尾部说明；无文件名 token 的 ref 如 CPG fullName 跳过不判）；
   - 标识符检查改为**逐 evidence entry 的 refs 并集**，且**只对
     `kind == "code_read"` entry 生效**（chain/taint entry 合法引用引擎事实）；
   - `_IDENT_STOPWORDS` 剔除 GET/POST/SQL/HTML/XML/CONFIRMED 等通用全大写
     词（它们不是代码标识符，曾是 violation 最大来源）。
   - 效果：全 5 target 仅剩 4 条真实 violation（引用文件无工具支撑等），
     全部 LIKELY 不触发降级；三个靶子证据零 violation。
3. **js-safe-03 XXE FP**（investigator.py prompt）：模型曾用 "parameter
   entity/DTD 理论" 绕过 `noent:false` 净化规则。已明确写死：libxmljs
   `{{ noent: false }}`（或省略 noent）= 不漏洞，仅凭理论判漏洞即 FP；
   只有代码中显式开启实体解析（`noent:true` 等）才判漏洞。**注意：
   `_BASE_PROMPT` 走 `.format()`，字面花括号必须写成 `{{ }}`**（踩过
   `KeyError: ' noent'`）。修后 xml.ts:18 判 False/SUSPICIOUS（TN）。
4. **refs 格式约束**（prompt）：refs 必须是裸 `file:start-end`；
   `code_read` entry 的标识符必须出现在所引行内。
5. hardened wrapper 规则（消 py-safe-03 的关键）未动，依然有效。

## 关键事实（新会话必读）

- **运行方式**：`uv run --offline agent/run_agent.py --target <name>
  [--limit N] [--only-sink <substr>] [--no-verify]`。**必须 `--offline`**：
  uv 联网解析 PEP723 依赖偶发 pypi TLS handshake eof，缓存完整可离线。
  verifier（M4）默认对 vulnerable finding 开启，`--no-verify` 关闭。
- **M4 验收**：`uv run --offline agent/smoke_verifier.py --target all`
  （依赖现有 findings.jsonl，强制 SAFE 样本为 vulnerable 验证 defender
  拦截；非零退出 = 有 FP 漏进 CONFIRMED 栏）。
- **M5 门禁**：`uv run --offline agent/run_agent.py --target all` 全量
  批量（并行 2）→ `python3 agent/run_baseline.py --compare`（默认取最新
  summary.json；recall 降或新 SAFE FP 即非零退出）。
- **注意 `--only-sink` 会整体重写 findings.jsonl**（只含匹配 sink）——
  调试验证后必须跑全量恢复配对，或参考本次 js 的做法：备份全量
  findings → 单 sink 重跑 → 按 run_agent.py main() 尾段逻辑（load →
  apply_validation → 重写 findings → score → render report）合并回全量
  并重生成 report。
- **后台任务默认 600s 超时**：全量回归必须 `run_in_background=true` +
  `disable_timeout=true`。5 target 顺序全跑约 40 分钟（joern 全缓存时）。
- **配额**：M3 期间 DeepSeek 多次 401/403（隔天自愈）。再遇到：把进度
  写进本文件后干净退出等恢复。今天（08-12）配额正常。
- **M3 验收标准**（计划 §8-M3）已全部满足，数字见上表。
- **红线**（计划 §9）保持：targets 只读；ground_truth 对 agent 工具不可见
  （read/search 硬拒绝）；不达标只许改 prompt/工具返回格式/预算/agent 侧代码。
- **已知泄漏面（待决策）**：investigator 的 `read_function` 工具**不剥**
  VULN:/SAFE: 注释（get_chain_snippets 和 M4 verifier 都剥）。M3 回归是
  带这个面跑出来的，改它会使 M3 结果不可直接对比；若要堵，一行
  `_strip_gt_tags` 包装 + 重跑全量回归即可。

## 已完成工作的要点

### M0：`agent/run_baseline.py`
- 用法：`python3 agent/run_baseline.py [--targets a,b] [--skip-llm] [--force]
  [--collect-only]`；每步缓存可断点续跑；`baseline.json` 是合并写（单 target
  重跑不会丢其它 target）。
- 冻结基线（`workspace/baseline/baseline.json`）：

  | target | chains CONFIRMED | A recall | B recall | B safe FP |
  |---|---|---|---|---|
  | python-flask | 22/25 | 10/10 | 7/7 | py-safe-02 |
  | java-spring | 21/22 | 8/10 | 7/7 | java-safe-02 |
  | js-ts-express | 24/35 | 10/10 | 7/7 | js-safe-02 |
  | csharp-aspnet | 22/32 | 10/10 | 6/7 | cs-safe-02 |
  | jsp-legacy | 29/32 | 9/10 | 7/7 | jsp-safe-05 |

- 与 2026-07 PROGRESS.md 数字的差异全部是工具/模型漂移（semgrep 1.168 命中
  更多 sink；DeepSeek 模型对 cmdi/XXE/IDOR 判定变严），已记录在 PROGRESS.md
  "Agent MVP — M0 baseline frozen" 一节。M5 回归门禁以这份新基线为准。
- 修过的坑（已固化进代码，勿回退）：
  - `joern-parse` 不在 PATH：`~/.local/bin/joern-cli/joern-parse`，env
    `JOERN_PARSE` 可覆盖（`config.py` 的 `find_joern_parse()`）；
  - semgrep 必须带 `--no-git-ignore`（JSP 树在 gitignored 的 `workspace/`
    下，否则 jsp 基线全断）；`run_baseline.py` 和 `pipeline.py` 都已加。

### M1：`agent/sast_agent/`（config / contracts / pipeline / tools）
- `pipeline.screen(target)` 产出 `InvestigationBrief` 队列（gap 分类
  OK/GAP_NO_CHAIN/GAP_FLOW_DEAD；GAP_MISSING_STORE 留 TODO 给 M3）。
- `tools.SastTools`：全部工具已实现并 smoke 过（`python3 agent/smoke_tools.py`，
  11 项 PASS），含 ground-truth 隔离、joern_query 四个参数化模板
  （callers_of/writes_to/reads_of/methods_in_file，连续失败 2 次返回强制
  手动接力提示）、CPG mtime 缓存（`workspace/agent-cache/<target>/`）。
- 已知偏差：callers_of 有 exact→contains 回退；sink key 匹配有 ±3 行就近
  兜底（joern 会把 semgrep 行号吸附到最近 call 节点）。

### M2：`investigator.py` / `report.py` / `run_agent.py`
- `uv run agent/run_agent.py --target python-flask [--limit N]`：screen →
  逐 sink 调查（M2 只挂 chains/taint/snippets/submit_finding 四个工具）→
  `workspace/agent-reports/<target>/{findings.jsonl,report.md}` + 评分。
- 验收：A 10/10、0 FP，13 条 finding 全带 stats，共 163k tokens。
- 关键设计：Finding 从 message history 的 `submit_finding` ToolCallPart 提取；
  `stats["chains"]` 存全部 chains 供 report 展开成 per-chain 评分（与 judge
  语义对齐）；`confidence_level` 由 report.py 机械映射（M2 暂行规则，
  TODO 指向 M4）；snippet 的 VULN:/SAFE: 注释在工具层剥掉。
- prompt 里的"hardened wrapper 规则"（确认流 ≠ 漏洞，看 sink 调用方式）
  是消 py-safe-03 FP 的关键，别删。

## M4 之后剩余工作（按子代理简报执行即可）

- ~~**M5**（计划 §8-M5）~~ 已完成（2026-08-15，见上"M5 实现要点"）。
  M4 数据点仍有效：verifier 使 token 翻 2.5–4 倍——sink 间并行
  （CPG/初筛全缓存，tools 只读）和 verifier 上下文裁剪是现成的优化点
  （M5 只做了 target 级并行 2）。
- ~~**M6**（计划 §7A）~~ 已完成（2026-09-03，见上"M6 实现要点"）。
- ~~**M7**（B 类 worker playbook + 缺席对比）~~ 已完成（2026-09-04，验收
  PASS 4/4 target，jsp-legacy 按用户决定排除、后于 2026-09-05 从仓库
  删除；见上"M7 实现要点"）。
- ~~**M8**（taxonomy 覆盖检查表入报告 + B 类回归门禁扩展）~~ 已完成
  （2026-09-05，见上"M8 实现要点"）。**AGENT_MVP_PLAN.md 的 M0–M8 里程碑
  至此全部关闭。** 后续方向见计划 §10（规则自进化、生产无 GT 运营等）。

## 环境速查

- 工具：`semgrep`/`joern` 在 PATH，`joern-parse` 见上；`uv`、`python3`。
  系统 python3 无 pydantic——sast_agent 相关脚本走 `uv run`（PEP 723）或
  smoke 脚本自带的 uv 重入。
- DeepSeek：env `DEEPSEEK_API_KEY`/`DEEPSEEK_MODEL`/`DEEPSEEK_BASE_URL`，
  `.env` → `~/Code/agent-demo/.env` 兜底（`config.py`）。
- 后台任务默认 600s 超时——跑全量回归要用 `run_in_background` +
  `disable_timeout` 或显式大 timeout（M2 踩过）。
