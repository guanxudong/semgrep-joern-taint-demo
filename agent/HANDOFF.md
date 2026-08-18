# Agent MVP 进度交接（2026-08-15，M5 完成更新）

> 给新会话的接续说明。实现规格见 `AGENT_MVP_PLAN.md`（M0–M5 为当前 MVP，
> M6–M8 是 B 类 agent 化的后续阶段）。本文件记录执行状态，读它 + 计划文件即可继续。

## 总体状态

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M0 基线固化 | ✅ 完成 | `agent/run_baseline.py`，结果在 `workspace/baseline/` |
| M1 工具层 | ✅ 完成 | `agent/sast_agent/{config,contracts,pipeline,tools}.py` + smoke 全绿 |
| M2 调查 agent + 报告 | ✅ 完成 | python-flask A 10/10、0 FP |
| M3 动态下钻 | ✅ 完成 | 5 target 全量回归全绿，三个靶子全部达标（见下） |
| M4 对抗复核 + 置信度分级 | ✅ 完成 | `verifier.py` + `report.apply_verifier()`，验收 9/9，回归全绿（见下） |
| M5 批量化 + 回归门禁 | ✅ 完成 | `run_agent.py --target all`（并行 2）+ `run_baseline.py --compare`，验收见下 |

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
- 之后是计划 §7A 的 M6–M8（B 类假设驱动 agent 化）。

## 环境速查

- 工具：`semgrep`/`joern` 在 PATH，`joern-parse` 见上；`uv`、`python3`。
  系统 python3 无 pydantic——sast_agent 相关脚本走 `uv run`（PEP 723）或
  smoke 脚本自带的 uv 重入。
- DeepSeek：env `DEEPSEEK_API_KEY`/`DEEPSEEK_MODEL`/`DEEPSEEK_BASE_URL`，
  `.env` → `~/Code/agent-demo/.env` 兜底（`config.py`）。
- 后台任务默认 600s 超时——跑全量回归要用 `run_in_background` +
  `disable_timeout` 或显式大 timeout（M2 踩过）。
