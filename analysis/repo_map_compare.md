# Repo Map 方案对比：tree-sitter vs Joern

日期：2026-07-23。目的：为任意代码仓库生成 LLM 可消费的结构地图（目录树 +
符号索引 + HTTP 路由表 + 文件级引用图），对比两条实现路线的准确度与成本。

- **方案 A**：`scripts/repo_map.py`（tree-sitter，`uv run` 直接跑，无前置依赖）
- **方案 B**：`analysis/joern/repo_map.sc`（Joern CPG 派生，需先 `joern-parse`）
- 两者输出同构 JSON（root/files[{path,role,language,imports,symbols,routes}]/references）。
- 核对脚本：`scripts/compare_repo_maps.py`，对照各 target 的 `ground_truth.json`
  （`entrypoint.route` / `entrypoint.function`）。

## 结果（四个 target，各 22 条 ground-truth 路由）

| 项目 | 指标 | tree-sitter | joern |
|---|---|---|---|
| python-flask | route / function 命中 | 22/22, 22/22 | 22/22, 22/22 |
| js-ts-express | route / function 命中 | 22/22, 19/22 | 22/22, 19/22 |
| java-spring | route / function 命中 | 22/22, 22/22 | 22/22, 22/22 |
| csharp-aspnet | route / function 命中 | 22/22, 22/22 | 22/22, 22/22 |
| py | 文件级引用边 | 20 | 11 |
| js | 文件级引用边 | 18 | 9 |
| java | 文件级引用边 | 12 | 9 |
| cs | 文件级引用边 | 10 | 5 |
| py | 符号数 | 48 | 48 |
| java | 符号数 | 60 | 61 |
| cs | 符号数 | 55 | 63 |
| — | 单项目耗时（CPG 已存在） | ~0.1 s | ~5 s（JVM 启动为主） |
| — | 前置条件 | 无 | 需先 joern-parse 生成 CPG |

复现命令：

```bash
# A
uv run scripts/repo_map.py targets/<dir> -o /tmp/a.md --json /tmp/a.json \
    --check targets/<dir>/ground_truth.json
# B（CPG 已存在于仓库根目录 <p>_cpg.bin）
SRC_ROOT=targets/<dir> joern --script analysis/joern/repo_map.sc <p>_cpg.bin \
    | awk '/^\{$/,/^\}$/' > /tmp/b.json     # joern 的 INFO 日志也走 stdout，需截取
# 对比
python3 scripts/compare_repo_maps.py --ground-truth targets/<dir>/ground_truth.json \
    /tmp/a.json /tmp/b.json --verbose
```

## 发现

1. **路由抽取两者打平**：四个框架（Flask/Express/Spring/ASP.NET）路由均 22/22，
   含蓝图/挂载前缀拼接（Flask `url_prefix`、Express `app.use` mount、
   Spring/ASP.NET 类级前缀）。tree-sitter 的启发式足以覆盖这些框架惯例，
   不需要 CPG 的语义信息。
2. **JS 的 3 个 function miss 是 ground-truth 的逻辑命名**（`getUser`、`listUsers`、
   `getOwnProfile`），源码里是匿名 arrow function，两条路线都无法恢复——19/22
   是 JS 目标的天花板，不是工具缺陷。匿名 handler 统一按路由路径派生稳定名字
   （如 `/users/search` → `search`），两条路线现在行为一致。
3. **引用图 tree-sitter 明显更密**：A 基于 import 解析（每个 import 一条边）；
   B 基于 CPG call 解析，jssrc2cpg 的 ghost call 和 csharpsrc2cpg 的弱解析导致
   边更少（cs 只有 5 条）。对"去哪找补全"这个用途，import 级边反而更直接可用。
4. **符号数基本持平**；joern 在 java/cs 略多（CPG 还收录了构造函数外的合成成员
   等），对地图用途无实质差别。joern 的 java/cs 签名来自 CPG（含类型），
   tree-sitter 的签名是源码截取，两者都可读。
5. **成本差距大**：tree-sitter 单项目 ~0.1 s、零前置、解析失败只丢一个文件；
   joern 需要先 parse（陌生仓库分钟级，且前端可能不支持该语言），
   脚本本身还有 JVM 启动开销。对"来了一个未知仓库先建图"的场景，
   joern 路线存在鸡生蛋问题。
6. **工程细节**：joern 把 INFO 日志打到 stdout，脚本 JSON 需用
   `awk '/^\{$/,/^\}$/'` 截取；`call.argument(1)` 在当前 Joern 版本返回节点
   而非 traversal，要用 `call.argument.argumentIndex(1).l`。

## 结论

**默认用方案 A（tree-sitter）做仓库地图**：准确度与 joern 持平（路由 100%），
引用图更密，快两个数量级，对未知仓库零前置。方案 B 保留作为 CPG 已存在时的
增强来源（真实 call 边、带类型签名），不构成独立建图路线——这也回答了最初
的工具选型问题：建地图用 tree-sitter，不需要为此引入 CPG。
