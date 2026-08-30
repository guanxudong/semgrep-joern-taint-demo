# Agent 调查实例：js-sqli-02（模块变量跨文件污点接力）

> 一次真实的 agent 动态下钻记录（2026-08-30），展示"确定性流水线失败 →
> agent 主动索取上下文 → 补齐调用链 → 对抗复核"的完整过程。
> 复现命令：
> `uv run --offline agent/run_agent.py --target js-ts-express --only-sink services/userService.js:14`
> （注意：`--only-sink` 会重写该 target 的 findings.jsonl / report.md）

## 1. 测试对象

Sink：`services/userService.js:14` 的 `db.query`（规则 `js-sink-sqli`）。

涉及的三个文件：

```js
// routes/users.js:16-22 —— HTTP 入口
// VULN: js-sqli-02 (sqli, cwe-89) [deep, taint via module field]
router.get('/lookup', (req, res) => {
  userService.stageName(req.query.name);
  userService.findStaged((err, rows) => {
    res.json(rows);
  });
});
```

```js
// services/userService.js:4-15 —— 污点经模块级变量跨函数传递
let pendingName = '';

function stageName(name) {
  pendingName = name;
}

function findStaged(cb) {
  const sql = "SELECT id, username, email FROM users WHERE username = '" + pendingName + "'";
  db.query(sql, cb);   // ← sink（第 14 行）
}
```

```js
// db/index.js:12-18 —— query() 裸执行；queryParams 是安全替代但此路径未用
function query(sql, cb) {
  pool.query(sql, cb);   // mysql2，无参数化
}

function queryParams(sql, args, cb) {
  pool.query(sql, args, cb);
}
```

## 2. 确定性初筛的结论：GAP_FLOW_DEAD

流水线（Semgrep → Joern backward chain → taint_confirm）对这个 sink 的结果：

- 调用链回溯只覆盖 `findStaged` 一段，**写入方 `stageName` 不在链上**
  （它是链的兄弟分支，不是中间环节）；
- 数据流确认失败：污点死在模块级变量 `pendingName` 的 store/load 之间
  ——Joern OSS 的已知盲区（见 `analysis/LIMITATIONS.md` §2）。

纯流水线到这里只能报 UNCONFIRMED。这正是 agent 下钻的入口信号。

## 3. Agent 的调查过程

共 **10 次工具调用，27.6 秒，36,781 tokens**。实际动作序列
（来自 finding 的 `stats.tool_log`）：

| # | 工具调用 | 目的与结果 |
|---|---|---|
| 1 | `get_taint_flows(sink)` | 确认引擎结论：流死在 `pendingName`（UNCONFIRMED） |
| 2 | `get_chains(sink)` | 链上只有 `findStaged`，缺写入方 |
| 3 | `get_chain_snippets(sink)` | 读链上源码，发现读了模块变量 `pendingName` |
| 4 | `read_function(services/userService.js, 1, 40)` | **找到缺失的写入点**：`stageName()` 写了 `pendingName` |
| 5 | `read_function(routes/users.js, 1, 40)` | **接回入口**：`GET /lookup` 调了 `stageName(req.query.name)` |
| 6 | `search_code("query\|queryParams", db/index.js)` | 确认 `db.query` 裸拼接执行，无参数化 |
| 7 | `get_repo_map()` | 核对路由归属 |
| 8 | `search_code("module.exports\|queryParams\|query", db/**)` | 排查是否存在封装/净化层 |
| 9 | `read_function(...)` | 补充阅读确认 |
| 10 | `submit_finding(...)` | 提交结论，结束调查 |

关键点：第 4、5 步就是"LLM 请求更多上下文"的机制——agent 发现链上缺
`pendingName` 的写入方，主动用 `read_function` 把链外的函数读进来，
像 IDE 的 "go to definition" 一样逐段把路径拼回去。

## 4. 补齐后的完整调用链

```
GET /lookup                                   ← HTTP 入口
  routes/users.js:17-22
    userService.stageName(req.query.name)     ← 污点存入模块变量
      services/userService.js:7-9  →  pendingName = name
    userService.findStaged(cb)
      services/userService.js:12-15
        sql = "... WHERE username = '" + pendingName + "'"
        db.query(sql, cb)                     ← sink (userService.js:14)
          db/index.js:12-14  →  mysql2 pool.query 裸执行
```

其中 `stageName → pendingName` 这一段是引擎看不见、由 agent 人工接力
补上的（finding reasoning 中原话："completed by manual relay across
stageName -> pendingName -> findStaged"）。

## 5. 最终 finding（结构化结论）

```json
{
  "sink":   {"id": "services/userService.js:14:js-sink-sqli", "name": "query"},
  "chain":  {"route": "GET \"/lookup\"",
             "path": ["routes/users.js:17-22",
                      "services/userService.js:7-9",
                      "services/userService.js:12-15"]},
  "verdict": {"is_vulnerable": true, "confidence": 0.95},
  "confidence_level": "LIKELY",
  "evidence": [
    {"kind": "code_read", "refs": ["services/userService.js:4-15"]},
    {"kind": "code_read", "refs": ["routes/users.js:16-22"]},
    {"kind": "code_read", "refs": ["db/index.js:12-18"]}
  ],
  "exploit_sketch": "GET /lookup?name=' OR '1'='1' --  —— 拼出 WHERE username = '' OR '1'='1' -- '，拖全表",
  "sanitizer_notes": "此路径无任何净化；queryParams 存在但 /lookup 未使用"
}
```

两条设计细节值得注意：

- **置信度诚实**：路径是人工接力补齐的（非引擎确认），所以级别是
  LIKELY 而不是 CONFIRMED；
- **证据可核查**：每段 evidence 都带 `file:line`，报告层会机械校验
  这些行在磁盘上真实存在、引用标识符真实出现，对不上自动降级——
  防 LLM 编路径。

## 6. 对抗复核（verifier）

对 `is_vulnerable=true` 的 finding 追加两轮独立判定（新 agent 实例，
只看 evidence 不看调查推理过程）：

- **attacker**：成功构造具体触发请求（exploit=yes）；
- **defender**：独立搜索 sanitizer，未找到（sanitizer=no，veto=False）。

两轮通过，维持 vuln=True / LIKELY。

## 7. 对比：流水线 vs agent

| | 确定性流水线 | agent 动态下钻 |
|---|---|---|
| 结论 | UNCONFIRMED（引擎盲区） | vuln=True，LIKELY 0.95 |
| 调用链 | 缺 `stageName` 写入环节 | 完整：入口 → 写入 → 读取 → sink |
| 证据 | 无 | 3 段带行号的 code_read + exploit sketch |
| 成本 | 几乎为 0 | 10 次工具调用 / 36.8k tokens / 27.6s |

这正是"流水线解决 80%，agent 啃 20%"的落地形态：确定性初筛便宜先行，
只有带 GAP 信号的 sink 才进入较贵的下钻循环。
