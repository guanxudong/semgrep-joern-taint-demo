# Category A 漏洞检测走查：Semgrep → Joern → LLM（python-flask 实战）

这份教程带你**亲手**把 category A（sink 类）漏洞的完整检测 pipeline 跑一遍。
目标项目是一个有 19 个漏洞 + 5 个安全对照样本的 Flask 靶子：`targets/python-flask`。
文中所有命令和输出都在本机实际执行验证过（2026-09-29），你可以逐条对照复现。

> 阅读姿势：每个 Stage 先讲"这一步回答什么问题"，再给命令和真实输出，
> 最后解释"你刚才看到了什么"。建议逐条复制命令执行，不要一次性全跑。

## Stage 0：总览——pipeline 的四个环节各管什么

```
 targets/python-flask 源码
        │
        ▼
 [1] Semgrep（模式匹配）      回答：哪里"长得像"危险操作？        → 嫌疑 sink 列表（会误报）
        │
        ▼
 [2] semgrep_to_sinks.py      回答：怎么把 Semgrep 结果交给 Joern？ → {file, line, rule} JSON
        │
        ▼
 [3] joern-parse              回答：代码的"图"长什么样？          → CPG（代码属性图）
        │
        ▼
 [4] Joern 脚本 ×3            回答：sink 从哪个 HTTP 入口可达？     → 调用链（backward_from_sinks）
                              回答：用户输入的污点真的流到了吗？   → CONFIRMED/UNCONFIRMED（taint_confirm）
                              回答：给 LLM 看的证据包是什么？     → 链上全部函数源码（extract_chain_snippets）
        │
        ▼
 [5] llm_judge_sink_chains.py 回答：语义上真的是漏洞吗？          → TP/FP verdict + 对照计分
```

一句话记忆：**Semgrep 管"找嫌疑"，Joern 管"两点确认"（可达性 + 污点流），LLM 管"语义裁决"。**

## Stage 1：认识样例——先用肉眼判断

开始之前，先读三段代码。`routes/users.py` 里有两个搜索接口：

```python
# targets/python-flask/routes/users.py:10-14  （样例 A）
@users_bp.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db.query_unsafe(f"SELECT id, username FROM users WHERE username LIKE '%{q}%'")
    return jsonify(rows)

# targets/python-flask/routes/users.py:31-35  （样例 B，对照组）
@users_bp.route("/search_safe")
def search_safe():
    q = request.args.get("q", "")
    rows = db.query_safe("SELECT id, username FROM users WHERE username LIKE ?", ("%" + q + "%",))
    return jsonify(rows)
```

样例 A 把用户输入 `q` 用 f-string 直接拼进 SQL——**教科书式 SQL 注入（TP）**。
样例 B 用参数化查询，`q` 只作为参数传入——**安全（FP 陷阱）**。

再看一个更刁钻的 TP（`routes/users.py:17-22`）：

```python
@users_bp.route("/lookup")
def lookup():
    name = request.args.get("name", "")
    user_service.stage_name(name)      # 污点先存进对象字段
    rows = user_service.find_staged()  # 另一个方法读字段、拼 SQL
    return jsonify(rows)
```

污点没有直接拼 SQL，而是被存进 `UserService._pending_name` 字段，另一个方法再读出来用
（见 `services/user_service.py:9-16`）。纯文本/模式匹配完全看不到这条链——这正是需要 Joern 的原因。

**记住三个样例**：`search`（TP 浅链）、`lookup`（TP 深链，过对象字段）、`search_safe`（安全对照）。

另外再记两个"消毒后仍会被报"的对照样例，后面 Stage 6/8 会用到：

- `routes/xml.py:18-22` `parse_xml_safe`：用的是 `defusedxml.ElementTree.fromstring`（安全解析器），
  但函数名带 `fromstring`，Semgrep 照样报（ground truth 里的 `py-safe-03`）。
- `services/file_service.py:16-21` `read_whitelisted`：`open()` 前有 `ALLOWED_FILES` 白名单检查，
  但 `open()` 本身是 sink（ground truth 里的 `py-safe-04`）。

## Stage 2：Semgrep 扫 sink——"哪里长得像危险操作"

打开规则文件 `analysis/rules/sinks-python.yml`，SQL 注入规则长这样：

```yaml
- id: py-sink-sqli
  pattern-either:
    - pattern: $CUR.execute($SQL)      # $CUR/$SQL 是 metavariable（元变量），可匹配任意表达式
    - pattern: $CUR.executemany($SQL, ...)
```

`$CUR.execute($SQL)` 的含义：任何接收器上名为 `execute`、且**恰好一个参数**的调用。
注意一个细节：Semgrep 默认按参数个数精确匹配，所以两参数的 `cur.execute(sql, params)`
（参数化查询）**不会**命中这条规则——后面会看到这件事带来了一个意外后果。

运行扫描（在仓库根目录）：

```bash
semgrep --config analysis/rules/sinks-python.yml targets/python-flask
```

**真实输出**（共 13 条 finding，节选）：

```
targets/python-flask/data/db.py
   ❯❱ analysis.rules.py-sink-sqli — SQL execute call (potential SQL injection sink)
        16┆ cur.execute(sql)
        37┆ cur.execute(sql)          # ← query_unsafe 和 execute_unsafe 都被报了

targets/python-flask/routes/xml.py
   ❯❱ analysis.rules.py-sink-xxe — XML parsing (potential XXE sink)
        13┆ parser = etree.XMLParser(resolve_entities=True, no_network=False)   # ← TP
        14┆ root = etree.fromstring(data, parser)                              # ← TP
        21┆ root = safe_et.fromstring(data)                                    # ← FP！defusedxml 安全解析器

targets/python-flask/services/file_service.py
   ❯❱ analysis.rules.py-sink-path-traversal — Filesystem open (potential path traversal sink)
        12┆ with open(path, "r") as f:     # ← TP
        20┆ with open(path, "r") as f:     # ← FP！前面有白名单检查
```

**你刚才看到了什么**：

- Semgrep 只认"函数名 + 参数形状"，不认识数据流、也不认识库语义。`xml.py:21` 用的明明是
  安全的 defusedxml，`file_service.py:20` 前面明明有白名单，都照报不误。
- 意外后果：`query_safe` 里的 `cur.execute(sql, params)`（两参数）**没有**被报——
  不是 Semgrep 理解参数化，只是参数个数不同碰巧躲开了。
  所以安全样例 `search_safe` 在这一步压根没进嫌疑名单。
- **结论：Semgrep 的输出是"嫌疑犯名单"，不是"定罪名单"。**

## Stage 3：格式转换——Semgrep JSON → Joern 输入

Joern 脚本不读 Semgrep 的原始 JSON，只需要每条的 `文件 + 行号 + 规则`：

```bash
semgrep --config analysis/rules/sinks-python.yml --json -o /tmp/py_demo_raw.json targets/python-flask
python3 scripts/semgrep_to_sinks.py /tmp/py_demo_raw.json --root targets/python-flask -o /tmp/py_demo_sinks.json
cat /tmp/py_demo_sinks.json
```

**真实输出**（13 条，节选）：

```json
[
  {"file": "data/db.py", "line": 16, "rule": "py-sink-sqli", "vuln_type": "sqli", "cwe": "89"},
  {"file": "data/db.py", "line": 37, "rule": "py-sink-sqli", "vuln_type": "sqli", "cwe": "89"},
  {"file": "routes/xml.py", "line": 21, "rule": "py-sink-xxe", "vuln_type": "xxe", "cwe": "611"},
  ...
]
```

`--root targets/python-flask` 把路径裁成相对路径，是为了和 CPG 里存的文件路径一致
（joern-parse 记的就是相对于扫描根目录的路径）——下一步的脚本靠 `file + line`
在图里精确定位那个调用节点。

## Stage 4：建 CPG——把代码变成图

CPG（Code Property Graph，代码属性图）是 Joern 的核心数据结构：把源码解析成一张图，
节点是函数/调用/参数/变量，边是 AST（语法树）、调用关系、数据流等。

```bash
joern-parse targets/python-flask --output /tmp/py_demo.cpg.bin
```

几十秒后得到一个二进制图文件，之后所有 joern 脚本都加载它、用查询语言在图上遍历。
（如果 `joern-parse` 不在 PATH，它在 `~/.local/bin/joern-cli/joern-parse`。）

> 副作用提示：joern 运行时会把 CPG 解包到当前目录下的 `workspace/py_demo.cpg.bin/`，
> 该目录是 gitignored 的，用完可删。

## Stage 5：回溯调用链——"sink 从哪个 HTTP 入口可达"

`analysis/joern/backward_from_sinks.sc` 做一件事：对每个 sink 调用，沿调用图**反向 BFS**，
一直走到一个 HTTP 入口（自动识别 `routes/*.py` 里的 Flask 路由函数）。脚本开头从环境变量
`SINKS_FILE` 读嫌疑列表。

```bash
SINKS_FILE=/tmp/py_demo_sinks.json CHAINS_JSON=/tmp/py_demo_chains.json \
  joern --script analysis/joern/backward_from_sinks.sc /tmp/py_demo.cpg.bin > /tmp/py_demo_backward.txt
grep -A8 'db.py:16' /tmp/py_demo_backward.txt | head -20
```

**真实输出**（sink `data/db.py:16` 部分——注意它有 4 条链）：

```
=== SINK execute  @ data/db.py:16  (in data/db.py:<module>.query_unsafe)
  -> routes/users.py:<module>.get_user
       routes/users.py:<module>.get_user
       services/user_service.py:<module>.UserService.find_by_id
       data/db.py:<module>.query_unsafe
  -> routes/users.py:<module>.lookup
       routes/users.py:<module>.lookup
       services/user_service.py:<module>.UserService.find_staged
       data/db.py:<module>.query_unsafe
  -> routes/users.py:<module>.search
       routes/users.py:<module>.search
       data/db.py:<module>.query_unsafe
  -> routes/admin.py:<module>.list_all_users
       routes/admin.py:<module>.list_all_users
       data/db.py:<module>.query_unsafe
```

**你刚才看到了什么**：

- 同一个 sink（`data/db.py:16`）有**多条链**：`search` 两步直达（浅链）；
  `lookup` 三步、中间穿过 `UserService.find_staged`（深链）——你 Stage 1 肉眼看过的样例都在。
- 调用链回答的是**可达性**：某个工具函数若从没被路由调用，会在这里显示
  `(no call-chain to any entrypoint found within depth limit)`，直接排除。
- 注意：可达 ≠ 有漏洞。链上走的是"谁调用了谁"，还没回答"用户输入是否到达 sink"。

## Stage 6：数据流确认——"用户输入真的流到了吗"

`analysis/joern/taint_confirm.sc` 用 Joern 的数据流引擎问一个精确的问题：
**从任何用户输入源（Flask 的 `request.args/form/json/...`，以及路由占位符参数）
到 sink 的危险参数，是否存在一条污点流？** 有 → `CONFIRMED`，没有 → `UNCONFIRMED`。

```bash
SINKS_FILE=/tmp/py_demo_sinks.json \
  joern --script analysis/joern/taint_confirm.sc /tmp/py_demo.cpg.bin \
  > /tmp/py_demo_taint.jsonl 2>/tmp/py_demo_taint.err
# joern 的 [INFO] 日志也混在 stdout 里，先过滤出 JSON 行再看：
grep '^{' /tmp/py_demo_taint.jsonl | jq -c '.sink as $s | "\($s.file):\($s.line)  \(.status)"'
```

**真实输出**：

```
"data/db.py:16  CONFIRMED"                      ← search / lookup / get_user / list_all_users 的污点都到了
"data/db.py:37  CONFIRMED"                      ← delete_user 的 user_id 来自路由占位符
"routes/profile.py:31  CONFIRMED"
"routes/render.py:10  CONFIRMED"
"routes/render.py:16  CONFIRMED"
"routes/tools.py:14  CONFIRMED"
"routes/tools.py:29  CONFIRMED"
"routes/xml.py:13  UNCONFIRMED"                 ← XMLParser(...) 构造器的参数全是常量，污点到不了
"routes/xml.py:14  CONFIRMED"                   ← 真正的 XXE 在这里：fromstring(data, parser)
"routes/xml.py:21  CONFIRMED"                   ← ⚠️ 这是 FP（defusedxml），污点确实"到达"了
"services/file_service.py:12  CONFIRMED"
"services/file_service.py:20  CONFIRMED"        ← ⚠️ 这也是 FP（allow-list）
"services/tool_service.py:14  CONFIRMED"
```

挑 `lookup` 深链的污点路径出来看（全场最佳）：

```bash
grep '^{' /tmp/py_demo_taint.jsonl | jq -c 'select(.sink.file=="data/db.py" and .sink.line==16)
  | .flows[] | select(.source_method | test("lookup")) | .path' | head -1
```

**真实输出**（保留原始细节，路径很长）：

```json
[
  {"file":"routes/users.py","line":19,"code":"request.args.get(\"name\", \"\")"},
  {"file":"routes/users.py","line":19,"code":"name"},
  {"file":"routes/users.py","line":20,"code":"name"},
  {"file":"services/user_service.py","line":9,"code":"name"},
  {"file":"services/user_service.py","line":11,"code":"self._pending_name = name"},
  {"file":"services/user_service.py","line":15,"code":"\"SELECT ... WHERE username = '%s'\" % self._pending_name"},
  {"file":"services/user_service.py","line":16,"code":"return db.query_unsafe(sql)"},
  {"file":"data/db.py","line":11,"code":"sql"},
  {"file":"data/db.py","line":16,"code":"cur.execute(sql)"}
]
```

（实际输出更长，中间还夹着 `tmp1`、`self`、`user_service` 等 AST 中间节点——
这是 pysrc2cpg 前端展开临时变量所致，属于噪音，看懂主干即可。）

**你刚才看到了什么**：

- 数据流引擎跨方法、甚至穿过**对象字段**（`self._pending_name = name` → 读回拼 SQL）
  追踪了污点——`lookup` 这条链靠肉眼或 grep 都极难确认，Joern 一步给出完整路径。
- `xml.py:13` 报 UNCONFIRMED 很有意思：Semgrep 对 XMLParser 构造器报了 XXE，但构造器的
  参数 `resolve_entities=True` 是常量，污点根本不在构造器上——真正的 sink 是下一行
  `fromstring(data, parser)`。数据流引擎比模式匹配精确。
- ⚠️ 但注意两个打 ⚠️ 的 sink：`xml.py:21` 和 `file_service.py:20` 也报 CONFIRMED。
  污点**确实**流到了 `safe_et.fromstring(data)` 和 `open(path)`——数据流引擎只回答
  "到没到"，不回答"到的路上有没有有效消毒"。**这就是还需要 LLM 的原因。**

## Stage 7：提取证据包——把链上源码喂给 LLM

数据流给出"是/否"，但 LLM 需要看**代码**才能做语义判断。
`analysis/joern/extract_chain_snippets.sc` 把每条链上所有方法的完整源码（从磁盘按
行号切片）打成 JSONL，一个 sink 一行、自包含：

```bash
SINKS_FILE=/tmp/py_demo_sinks.json SRC_ROOT=targets/python-flask \
  joern --script analysis/joern/extract_chain_snippets.sc /tmp/py_demo.cpg.bin \
  > /tmp/py_demo_snippets.jsonl 2>/dev/null
grep '^{' /tmp/py_demo_snippets.jsonl | jq -c '.sink as $s | "\($s.file):\($s.line) chains=\(.chains|length)"'
```

**真实输出**：

```
"data/db.py:16 chains=4"        "data/db.py:37 chains=2"        "routes/profile.py:31 chains=1"
"routes/render.py:10 chains=1"  "routes/render.py:15 chains=1"  "routes/tools.py:14 chains=1"
"routes/tools.py:29 chains=1"   "routes/xml.py:14 chains=1"     "routes/xml.py:21 chains=1"
"services/file_service.py:12 chains=1"  "services/file_service.py:20 chains=1"  "services/tool_service.py:14 chains=1"
```

每行长这样（节选 `xml.py:21`）：

```json
{"sink":{"name":"fromstring","file":"routes/xml.py","line":21,
         "in_method":"routes/xml.py:<module>.parse_xml_safe","rule":"py-sink-xxe","vuln_type":"xxe"},
 "chains":[{"entrypoint":"routes/xml.py:<module>.parse_xml_safe","calls":["routes/xml.py:<module>.parse_xml_safe"]}],
 "snippets":[{"function":"routes/xml.py:<module>.parse_xml_safe","file":"routes/xml.py",
              "start_line":19,"end_line":22,"code":"def parse_xml_safe():\n    data = request.get_data()\n    root = safe_et.fromstring(data)\n    ..."}]}
```

两个细节：

- `SRC_ROOT=targets/python-flask` 告诉脚本去磁盘哪个根目录切源码；`snippets` 是链上所有
  函数源码的去重并集——**LLM 看到的就是这些**。
- 13 条 finding 这里只匹配出 12 个 sink：该脚本的行号窗口比 `taint_confirm` 严格
  （±1 行 vs ±3 行），`xml.py:13` 的构造器调用被合并覆盖了——它跟 `xml.py:14` 指向同一个
  XXE，不影响结果。另外 `render.py` 的 sink 行号 15 和 Semgrep 报的 16 差 1 行，是
  AST 节点边界与文本行号的正常偏差。

## Stage 8：LLM 语义裁决——真漏洞还是误报

`scripts/llm_judge_sink_chains.py` 用 pydantic-ai 调 DeepSeek（OpenAI 兼容接口），
对每个 sink 的每条链发一次判定。系统 prompt（脚本内 `SYSTEM_PROMPT`）要求 LLM
按三条判据推理：① 攻击者输入是否真的流到 sink 危险参数；② 链上是否有**有效**消毒
（参数化查询、白名单、实体禁用等，表面检查不算）；③ 代码是否在入口到 sink 的路径上。
输出结构化结果 `is_vulnerable / confidence / reasoning`。

```bash
uv run scripts/llm_judge_sink_chains.py \
  --snippets /tmp/py_demo_snippets.jsonl \
  --ground-truth targets/python-flask/ground_truth.json \
  -o /tmp/py_demo_verdicts.jsonl
```

**真实 verdict 节选**（`lookup` 深链 TP）：

```
is_vulnerable: true   confidence: 0.95
reasoning: "The HTTP entrypoint reads request.args['name'] and passes it to
stage_name, which stores it as self._pending_name (used later by find_staged).
find_staged interpolates that value directly into a SQL string via '%s' %
self._pending_name and hands the result to db.query_unsafe, which calls
cur.execute(sql) with no parameterization. There is no sanitization, escaping,
or allow-list anywhere on the path..."
```

**真实 verdict 节选**（两个 Stage 6 翻不了案的 FP，在这里被翻案）：

```
[routes/xml.py:21]  is_vulnerable: false   confidence: 0.85
  "The alias `safe_et` and the function name `parse_xml_safe` strongly indicate
   the use of a hardened XML parser (e.g., defusedxml.ElementTree) that disables
   external entity resolution by default... this is likely a false positive from
   Semgrep's generic `fromstring` rule."

[services/file_service.py:20]  is_vulnerable: false   confidence: 0.9
  "The user-controlled `name` ... is validated against an exact-membership
   allow-list (`if name not in ALLOWED_FILES: raise ValueError`) before being
   joined to UPLOAD_DIR and passed to open()... effective allow-list sanitization
   on the direct path."
```

**脚本最后的自动计分**（对照 `ground_truth.json`）：

```
Recall category A (sink-based):  10/10 = 100%
Recall category B (non-sink):    0/7 = 0%   (sink pipeline 管不到，符合预期)
Safe-sample false positives:     none        (py-safe-01/03/04 全部正确判安全)
TP=10 FN=7 FP=0 TN=5 LLM errors=0
```

**你刚才看到了什么**：

- 数据流报 CONFIRMED 的两个 FP（defusedxml、allow-list），LLM 看了源码后正确翻案——
  这是整个 pipeline 里 LLM 层的核心价值：**污点"到没到"是图的问题，"到了能不能用"
  是语义的问题。**
- category A 召回 10/10、安全样本 0 误报：三个环节各排除一类噪音后，剩下的判定质量很高。
- 反向也成立：LLM 可能对真漏洞过度谨慎（见 `analysis/LIMITATIONS.md` §4），
  所以 ground truth 对照计分是衡量这一层的必要手段，不是可选项。

## 收尾：一张表记住每个环节过滤了什么

| 环节 | 回答的问题 | 本例中的表现 | 典型错误倾向 |
|---|---|---|---|
| Semgrep | 哪里像危险操作 | 13 个嫌疑（含 defusedxml、白名单 2 个误报） | 过报（不认数据流/库语义） |
| Joern 调用链回溯 | sink 从哪个 HTTP 入口可达 | db.py:16 找出 4 条链（浅链 2 跳、深链 3 跳） | 动态调用解析不出时断链 |
| Joern 数据流确认 | 用户污点是否到达 sink | 12 CONFIRMED / 1 UNCONFIRMED；但 2 个消毒后的 FP 也 CONFIRMED | 字段/容器敏感分析不完整时漏报 |
| LLM 语义裁决 | 到达的污点是否可利用 | 翻案 defusedxml + allow-list 两个 FP；A 类 10/10 | 过度谨慎漏报 / 被表面检查骗过 |

各环节的错误倾向记录在 `analysis/LIMITATIONS.md`，优化决策记录在 `DECISIONS.md`。

## 自己动手

1. **看污点路径**：`grep '^{' /tmp/py_demo_taint.jsonl | jq` 挑任意 CONFIRMED sink，
   把 `.flows[].path` 逐行读一遍——每一段都是真实代码行。
2. **思考题**（不要改 `targets/`，在心中推演即可）：如果把 `search_safe` 改成
   `db.query_unsafe("... LIKE '%" + q + "%'")`，Stage 6 里 `data/db.py:16` 的输出
   会有变化吗？（答案：sink 行没变，但 `search_safe` 会变成一条新链新流——Semgrep 阶段
   它碰巧没被报，纯粹因为 `query_safe` 两参数调用不匹配单参数模式；这正是"Semgrep 靠
   形状、Joern 靠语义"的最佳注脚。）
3. **思考题**：`data/db.py:37`（execute_unsafe）的链终点之一是 `delete_user`，参数来自
   路由占位符 `/<int:user_id>`。为什么 Joern 把路由参数也算作污点源？
   看 `taint_confirm.sc` 里 python 分支的 `placeholderCalls` 逻辑——pysrc2cpg 不给
   Flask 装饰器建注解节点，脚本改用"route 调用行下方最近的方法"来识别处理器及其参数。
4. **只重放计分**（不再调 API）：`uv run scripts/llm_judge_sink_chains.py
   --from-verdicts /tmp/py_demo_verdicts.jsonl
   --ground-truth targets/python-flask/ground_truth.json`
5. **换个靶子**：同一套命令把 `python-flask` 换成 `js-ts-express`（规则文件
   `sinks-js.yml`、CPG 换个文件名），体会 pipeline 与语言无关的部分在哪里、
   语言相关的部分在哪里（sink 名称表、入口识别、污点源正则，见 joern 脚本顶部的
   `sinkNames` / `entrypoints` / `callSourceRe`）。
6. **打开黑盒**：想看懂三个 joern 脚本内部在干什么（反向 BFS、污点源识别、
   `reachableByFlows`、行号窗口匹配），继续读姊妹篇
   `docs/joern-scripts-internals.md`，里面有一组可交互验证的查询练习。
