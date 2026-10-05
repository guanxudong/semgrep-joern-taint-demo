# Joern 脚本内部解析：它们到底干了什么

本文是 `docs/category-a-python-walkthrough.md` 的姊妹篇。上一篇讲了 pipeline 每个环节的
输入输出；这一篇打开 `analysis/joern/` 下三个核心脚本的黑盒，逐节解释代码在干什么，
并给你一组可以在本机直接跑的交互式查询来验证理解。

脚本：`backward_from_sinks.sc`（回溯调用链）、`taint_confirm.sc`（污点确认）、
`extract_chain_snippets.sc`（提取证据包）。演示 CPG 沿用上一篇的
`/tmp/py_demo.cpg.bin`（没有就先 `joern-parse targets/python-flask --output /tmp/py_demo.cpg.bin`）。
文中所有查询输出都是真实跑出来的。

## 0. 前置知识：joern 脚本是什么

`joern --script xxx.sc <cpg.bin>` 加载 CPG 后执行一段 **Scala 代码**——不是独立语言，
就是 Scala + Joern 的查询库（`semanticcpg` DSL）。三个关键点：

- 全局变量 `cpg` 是图的入口，`cpg.method`、`cpg.call`、`cpg.file` 等返回**遍历对象**
  （Traversal），可以链式过滤、取值，`.l` 收尾变成 List。
- 脚本之间传参不走命令行参数，走**环境变量**（`SINKS_FILE`、`SRC_ROOT`、`CHAINS_JSON`）。
- joern 自己的 `[INFO]` 日志也往 stdout 打，所以脚本输出的 JSON 行要 `grep '^{'` 过滤。

本次用到的查询操作小抄（每个后面都有实战）：

| 操作 | 含义 | 注意 |
|---|---|---|
| `cpg.method / cpg.call / cpg.file / cpg.parameter` | 全图对应类型节点 | 一切查询的起点 |
| `.name("regex")` | 按 name 属性正则过滤 | 参数是**正则**，不是字符串相等 |
| `.nameExact("s")` | name 属性**精确相等** | 匹配的是 `name`，不是 `fullName`（§6 有翻车实录） |
| `.fullName` | 方法的全名，python 形如 `data/db.py:<module>.query_unsafe` | 定位方法主要靠它 |
| `.where(f) / .filter(f)` | 谓词过滤（`.where` 可链到子遍历） | |
| `.ast` | 节点的整棵子语法树 | `cpg.file(...).ast.isMethod` = 文件里所有方法 |
| `.argument` | 调用节点的实参 | 数据流查询的起点 |
| `.method` | 调用节点所在的方法 | |
| `.caller` | **沿调用图反向一步**：谁调用了这个方法 | 回溯的核心 |
| `.reachableByFlows(sources)` | **数据流引擎**：从 sources 到当前节点是否存在污点路径 | 污点确认的核心 |
| `.file.name.headOption` | 节点所在文件路径 | 每个 AST 节点都有 |
| `.l / .headOption` | 收尾：变 List / 取第一个 | |

## 1. 三个脚本的共同骨架

三个脚本前 2/3 几乎是同构的，只有最后一步不同：

```
① 语言嗅探：看 CPG 里有没有 .cs / .java / .py 文件，确定 lang
② sink 名称表：每个语言一份正则（execute|eval|open|...），与 semgrep 规则对齐
③ entrypoints 字典：枚举 HTTP 入口方法（python：routes|api/*.py 的顶层方法）
④ SINKS_FILE → CPG 调用节点：按 file+line 在 ±N 行窗口内找候选，
   "名称优先"挑出真正的 sink 调用
────────── 以上三个脚本共享 ──────────
⑤ backward_from_sinks : 反向 BFS 找链
   taint_confirm      : 数据流 reachableByFlows
   extract_snippets   : 反向 BFS + 按行号从磁盘切源码
```

为什么 ④ 需要"名称优先"匹配？Semgrep 只给 `{file, line}`，但一行代码里可能有多个调用
节点（比如 `etree.fromstring(data, parser)` 一行上有 `fromstring` 和参数里的构造器）。
脚本用 `sinkNameKind` 给候选打分：调用名命中 sink 表（0 分最优）< methodFullName 命中（1）
< 代码文本里出现 `new Xxx`（2）< 都不命中（3），窗口内取最优、距离最近的。

## 2. `backward_from_sinks.sc`：反向 BFS 找链

核心函数（脚本 218-233 行），很短：

```scala
def backward(sinkCall: Call, maxDepth: Int = 8): List[List[Method]] = {
  var results = List.empty[List[Method]]
  var queue = List(List(sinkCall.method))          // 起点：sink 调用所在的方法
  while (queue.nonEmpty) {
    val path = queue.head; queue = queue.tail
    val cur = path.head                            // 当前链头
    if (entrypoints.contains(cur.fullName)) {
      results ::= path                             // 链头到达 HTTP 入口 → 记录
    } else if (path.size <= maxDepth) {
      cur.caller.l.foreach { caller =>             // 沿调用图反向一步
        if (!path.exists(_.fullName == caller.fullName))   // 防环
          queue :+= caller :: path                 // 把 caller 接到链头，入队
      }
    }
  }
  results
}
```

三个设计点：

- **`.caller` 是整个脚本的发动机**：joern 的调用图边，一步从被调方法跳到所有调用者。
  真正的"图数据库"能力就这一句，其余全是普通的队列循环。
- **`maxDepth = 8` + 防环**：调用图里可能有递归/回边，不限深会爆；同一链上不重复出现
  同一方法。
- **SHALLOW 情况**：sink 就在入口函数里（比如 `pickle.loads` 在 `import_profile` 里），
  链长为 1，单独打印一行提示。

用真实数据走一遍 BFS（sink `data/db.py:16` 在 `query_unsafe` 里）：

```
第 0 层: query_unsafe
第 1 层: .caller → search, list_all_users, find_staged, find_by_id, find_by_name
         ├─ search          是入口 ✓ → 链1: search → query_unsafe
         ├─ list_all_users  是入口 ✓ → 链2: list_all_users → query_unsafe
         ├─ find_staged     不是入口 → 继续
         ├─ find_by_id      不是入口 → 继续
         └─ find_by_name    不是入口 → 继续
第 2 层: find_staged.caller → lookup ✓ → 链3: lookup → find_staged → query_unsafe
         find_by_id.caller  → get_user ✓ → 链4: get_user → find_by_id → query_unsafe
         find_by_name.caller → 空（没有任何路由调它）→ 死胡同，丢弃
```

最终 4 条链，和 walkthrough 里的输出一致。注意 `find_by_name` 这条**死胡同**：
它确实调用了 `query_unsafe` 也拼了 SQL，但没有 HTTP 入口可达——pipeline 层面它就是
"不可达的嫌疑"，不会进入后续环节。这就是调用链回溯过滤掉的那类噪音。

> 脚本里还有两段 python 用不上的补偿逻辑，知道存在即可：JS 的 ghost-callee 修复
> （jssrc2cpg 解析不了 require 导入的跨文件调用边，脚本按"导入路径 + 调用名"手动补边，
> 对应 DECISIONS.md D5）和 C# 的文本 fallback（csharpsrc2cpg 丢失嵌套调用节点，
> 按方法源码里出现 `.方法名(` 补边，D7）。它们揭示了一个事实：**每个语言前端都有
> 建边缺陷，图查询的可靠性取决于前端的成熟度**。

## 3. `taint_confirm.sc`：污点源 → sink 的数据流

### 3.1 污点源（sources）的两种形态

```scala
// ① 调用型：request.* 访问器（python 分支，脚本 43 行）
".*request\\.(args|form|values|cookies|headers|json|data|get_data|get_json|view_args).*"

// ② 参数型：路由占位符绑定的处理器参数（脚本 70-78 行）
val placeholderCalls = cpg.call.name("^(route|get|post|...)$")
  .where(_.argument.code(".*(<[^>]+>|[{][^{}]+[}]).*")).l    // 路由字符串里含 <xxx> 或 {xxx}
val routeHandlers = placeholderCalls.flatMap { c =>
  c.file.ast.isMethod                                          // 同文件所有方法
    .filter(m => m.lineNumber.getOrElse(-1) > c.lineNumber.getOrElse(Int.MaxValue))
    .sortBy(_.lineNumber.getOrElse(-1)).l.headOption           // route 调用行下方最近的方法
}
cpg.call.code(callSourceRe).cast[CfgNode] ++ routeHandlers.flatMap(_.parameter.l)
```

② 是一段"绕缺陷"的逻辑，值得细读：Flask 的 `@bp.route("/users/<int:user_id>")` 会把
URL 里的参数绑到处理器函数参数上，但 **pysrc2cpg 不给装饰器建注解（ANNOTATION）节点**，
没法像 Java/C# 那样"找带某注解的参数"。替代办法：找到含占位符的 route 调用（装饰器
在 CPG 里就是个普通调用节点），取它**下方行号最近的方法**，把它的参数当污点源。
本靶子上识别出 3 处（实测输出）：

```
routes/admin.py:15  admin_bp.route("/users/<int:user_id>", methods = ["DELETE"])
routes/users.py:25  users_bp.route("/<int:user_id>")
routes/users.py:38  users_bp.route("/me/<int:user_id>")
```

这就是 `delete_user(user_id)` 的 `user_id` 能被算作污点源的原因。

### 3.2 核心就一行

```scala
val flows = s.argument.reachableByFlows(sources).l   // 脚本 169 行
```

`reachableByFlows` 是 joern 数据流引擎的入口：给定一组源节点，回答"从任一源到当前节点
（sink 调用的实参）是否存在数据依赖路径"，返回完整路径（不只 yes/no）。它跨方法、
跨文件、穿过赋值/拼接/字段读写（`self._pending_name` 这种），这就是 walkthrough 里
`lookup` 深链能被确认的原理。

### 3.3 输出整形（脚本 173-191 行）

- 按路径签名去重（同一物理路径可能由引擎报多次）；
- **每个入口方法最多保留 3 条流**——防止一个路由的重复路径挤掉其他路由的证据；
- 流的第一步用 `attributeSource` 归属到方法（JS 的匿名 lambda 会被解析成
  `GET /users/search` 这样的路由标签；python 分支直接用"行号落在哪个方法行区间内"的
  `methodOf`）。

### 3.4 为什么 `xml.py:13` 是 UNCONFIRMED

回头看这个真实案例就通了：sink 候选是 `etree.XMLParser(resolve_entities=True, no_network=False)`
这个调用，它的**实参是两个常量**。数据流引擎问"有源流到这些实参吗"——没有，
UNCONFIRMED。而下一行 `etree.fromstring(data, parser)` 的实参 `data` 来自
`request.get_data()`——CONFIRMED。同一行代码级别的差别，模式匹配给不出。

## 4. `extract_chain_snippets.sc`：把链变成 LLM 能读的证据

前半部分与 backward 相同（BFS 找链），新增两件事：

### 4.1 取源码：`methodSource`（脚本 28-41 行）

```scala
// 磁盘切片（按方法起止行号从源文件切）和 CPG 的 code 属性，谁长用谁
(m.file.name.headOption, m.lineNumber, m.lineNumberEnd) match {
  case (Some(f), Some(start), Some(end)) if end > start =>
    val sliced = 磁盘切片(srcRoot.resolve(f), start, end)
    if (sliced.length > cpgCode.length) sliced else cpgCode
```

为什么"谁长用谁"？有些前端（javasrc2cpg）把方法的 `code` 属性只填成**签名行**，
方法体全丢——那样 LLM 拿到的证据就是残的。磁盘切片兜底，所以必须设
`SRC_ROOT=targets/python-flask` 告诉它源文件根在哪。

### 4.2 打包（脚本 221-245 行）

- `methods`：链上所有方法按 fullName 去重的**并集**（一个 sink 多条链时，证据不重复）；
- 每个 sink 输出一整行 JSON：`{sink, chains, snippets}`——`snippets` 里每段带
  `file/start_line/end_line/code`，这就是 LLM 判定时读的全部内容。

与 taint_confirm 的一个真实差异：这个脚本的行号窗口是 **±1**（taint_confirm 是 ±3），
所以 13 条 finding 只匹配出 12 个 sink——`xml.py:13` 的构造器调用被 `xml.py:14`
的 `fromstring` 合并覆盖。副作用无害（同一个 XXE），但它提醒你：**每个脚本的
sink 匹配策略是独立调参的，数字不完全一致是正常的。**

## 5. 自己动手：交互式查询

推荐用一次性脚本跑（比 REPL 好复制）。写 `/tmp/probe.sc`，然后
`joern --script /tmp/probe.sc /tmp/py_demo.cpg.bin 2>/dev/null | grep -v '^\[INFO\]'`。
以下每条查询都附真实输出，你可以边跑边对照。

**Q1：按名字找方法**

```scala
cpg.method.name("lookup").l.foreach(m =>
  println(s"${m.fullName}  file=${m.file.name.headOption.getOrElse("?")}  lines=${m.lineNumber.getOrElse(-1)}..${m.lineNumberEnd.getOrElse(-1)}"))
// → fullName=routes/users.py:<module>.lookup  file=routes/users.py  lines=18..24
```

**Q2：所有 `execute` 调用节点（Semgrep 报的 2 个 + 它没报的 1 个都在图里）**

```scala
cpg.call.name("execute").l.foreach(c =>
  println(s"${c.file.name.headOption.getOrElse("?")}:${c.lineNumber.getOrElse(-1)}  ${c.code}  所在方法=${c.method.fullName}"))
// → data/db.py:16  cur.execute(sql)          所在方法=data/db.py:<module>.query_unsafe
// → data/db.py:27  cur.execute(sql, params)  所在方法=data/db.py:<module>.query_safe
// → data/db.py:37  cur.execute(sql)          所在方法=data/db.py:<module>.execute_unsafe
```

**Q3：一层回溯——谁调用了 `query_unsafe`**（§2 BFS 的第 1 层）

```scala
cpg.method.name("query_unsafe").caller.fullName.l.foreach(println)
// → routes/admin.py:<module>.list_all_users
// → routes/users.py:<module>.search
// → services/user_service.py:<module>.UserService.find_staged
// → services/user_service.py:<module>.UserService.find_by_name     ← 死胡同
// → services/user_service.py:<module>.UserService.find_by_id
```

**Q4：枚举 HTTP 入口**（python 分支的识别逻辑，24 个）

```scala
cpg.file.name("routes/.*\\.py$").ast.isMethod
  .filter(m => m.fullName.matches("routes/[^:]+:<module>\\.[A-Za-z_][A-Za-z0-9_]*"))
  .fullName.l.foreach(println)
// → routes/admin.py:<module>.list_all_users, delete_user, routes/users.py:<module>.search, ...
```

**Q5：数污点源**（注意输出里的噪音）

```scala
cpg.call.code(".*request\\.(args|form|...|view_args).*").l.size
// → 83
```

83 比"源码里 request 出现的次数"多得多，因为 pysrc2cpg 会把 `q = request.args.get("q", "")`
展开成多个节点（`request.args`、`tmp0 = request.args`、`request.args.get(...)`、
`q = tmp0 = ...`），每个 code 都匹配正则。数据流路径里出现的 `tmp1`、`self`、`cur`
等"幽灵节点"也是同一个原因——**这是前端展开临时变量留下的噪音，不是 bug，看懂主干即可。**

**Q6：手动跑一次污点确认**（复刻 taint_confirm 对 `lookup` 深链的判断）

```scala
import io.shiftleft.codepropertygraph.generated.nodes
val srcs = cpg.call.code(".*request\\.(args|form|values|cookies|headers|json|data|get_data|get_json|view_args).*")
  .cast[nodes.CfgNode]
val sink = cpg.call.name("execute").where(_.file.name("data/db.py"))
  .filter(_.lineNumber.getOrElse(-1)==16).l.head
sink.argument.reachableByFlows(srcs).l
  .filter(p => p.elements.l.headOption.exists(e =>
    e.file.name.headOption.getOrElse("?") == "routes/users.py" && e.lineNumber.getOrElse(-1) == 19))
  .take(1).foreach { path => path.elements.l.foreach { e =>
    println(s"${e.file.name.headOption.getOrElse("?")}:${e.lineNumber.getOrElse(-1)}  ${e.code.take(60)}") } }
```

真实输出（对照 `taint_confirm.sc` 产物一致；已去掉 `self`、`user_service`、`cur` 等噪音行）：

```
routes/users.py:19  request.args.get("name", "")
routes/users.py:19  tmp1 = request.args | request.args.get("name", "")
routes/users.py:19  name
routes/users.py:20  name
services/user_service.py:9  name
services/user_service.py:11  name
services/user_service.py:11  self._pending_name      ← 污点写入对象字段
services/user_service.py:15  self._pending_name      ← 字段读回
services/user_service.py:15  "SELECT ... WHERE username = '%s'" % self._pending_name
services/user_service.py:15  sql
services/user_service.py:16  sql
data/db.py:11  sql
data/db.py:16  sql                                    ← 到达 sink 实参
```

## 6. 我踩过的一个坑：`.nameExact` ≠ `.fullName`

写 Q3 的查询时，我第一版用的是：

```scala
cpg.method.nameExact("data/db.py:<module>.query_unsafe").caller.l   // → 空！
```

结果为空，但 `.name("query_unsafe").caller` 明明有 5 个 caller。排查后发现：
**`nameExact` 匹配的是节点的 `name` 属性（精确相等），不是 `fullName`**——那个长串
是 fullName，name 只是 `query_unsafe`。要按 fullName 精确定位应该用
`.fullNameExact("...")` 或 `.where(_.fullName == "...")`。
（反过来 `.name(...)` 的参数是**正则**，写 `.name("data/db.py:...")` 也不会相等匹配。）

这个坑的价值在于：joern 脚本报"空结果"时，先怀疑**查询写错了**（属性名/正则/精确匹配），
再怀疑图里没有——用 `cpg.method.where(_.file.name("data/db.py")).fullName.l`
把原始数据打出来对照，是最快的排错方式。

## 7. 想再深入

- `analysis/joern/find_entrypoints.sc`：entrypoints 字典的独立版，四种语言的入口识别
  写法都在里面（Java/C# 靠注解节点，JS 靠 route 调用 + METHOD_REF）。
- `analysis/joern/forward_from_entrypoints.sc` 与 `extract_entrypoint_snippets.sc`：
  方向相反（入口向下），是 category B 流程的零件。
- joern 官方查询文档：`reachableByFlows`、`.caller`、`.ast` 等的完整语义见
  https://docs.joern.io/traversal-basics/ 。
- 前端能力的边界决定了图的质量：`analysis/LIMITATIONS.md` §1–2 记录了本仓库实测到的
  各语言前端缺陷（JS ghost callee、C# 丢嵌套调用等）。
