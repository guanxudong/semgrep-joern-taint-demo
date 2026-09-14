# Perl 降级模式设计:无引擎语言接入 benchmark 的方案

日期:2026-09-14 · 状态:**仅设计,未实施** · 决策记录:DECISIONS.md D10

本文回答:当目标语言缺少 Semgrep grammar 和/或 Joern frontend 时(以 Perl
为实例),如何接入本 benchmark 管线。本轮只产出设计,不改管线代码。

## 1. 事实核查(2026-09-14 核实)

两个常见误解需要先纠正:

- **"Semgrep 没有语言依赖"——不成立。** Semgrep 每种语言需要独立 grammar。
  查[官方支持列表](https://docs.semgrep.dev/supported-languages):PHP 是
  GA(支持跨函数数据流、50+ Pro rules);**Perl 完全不在列表中**,连
  experimental 档(Bash/Lua/Dart 等)都没有。Semgrep 对 Perl 唯一能做
  的是 `--lang generic`(纯文本模式匹配,无 AST、无数据流)。
- **"Joern 不支持 PHP"——不成立。** Joern 官方前端列表包含
  [php2cpg(`--language PHP`)](https://docs.joern.io/frontends/)。注意:
  它底层调 PHP-Parser,**要求分析机安装 PHP 运行时**;成熟度低于
  pysrc2cpg/jssrc2cpg(例:2026-06 仍有动态调用生成空 call 节点的
  [issue](https://github.com/joernio/joern/issues))。Joern 没有 Perl
  前端,也无任何 roadmap 迹象。

工具支持矩阵:

| 语言 | Semgrep | Joern | tree-sitter-language-pack |
| --- | --- | --- | --- |
| 现有 4 语言(py/java/js/cs) | GA | 有前端 | 自带 grammar |
| PHP | GA(跨函数数据流) | php2cpg(需 PHP 运行时) | 自带 grammar |
| Rust/Lua/Bash 等 | GA 或 experimental | **无前端** | 大多自带 |
| Perl | **不支持** | **无前端** | 自带 grammar(tree-sitter-perl,各平台 wheel 可用性实施时验证) |

本 repo 代码现状(与本文引用的行号已逐一核对):

- 7 个 `.sc` 脚本共用 4 分支语言嗅探,**未知语言静默回落 `"js"`**
  (如 `analysis/joern/backward_from_sinks.sc:52-55`)——将来加任何语言
  的第一陷阱。
- **不存在 no-joern 模式**:A 类筛查死在 `ensure_cpg`
  (`agent/sast_agent/pipeline.py:135-137`,joern-parse 失败直接抛
  RuntimeError),B 类 worker 死在 `get_forward_slice`
  (`agent/sast_agent/worker.py:179-184`)。唯一已设计的降级是
  `joern_query` 连续失败 2 次后转人工接力提示
  (`agent/sast_agent/tools.py:48-50`,重试上限
  `agent/sast_agent/config.py:39`)。
- B 类 **planner 本就 joern-free**(`agent/sast_agent/planner.py:115-118`
  只消费 tree-sitter 的 `repo_map.json`)。
- sink 数据契约:`scripts/semgrep_to_sinks.py:39-47` 输出
  `{file, line, rule, vuln_type, cwe}` JSON 数组——任何替代 sink 源
  只要产出同一 schema 即可无缝接入下游。
- 证据引用扩展名硬编码 3 处:`report.py:413`、`investigator.py:173`、
  `worker.py:129`(均为 `(?:py|js|ts|java|cs|jsp)`)。
- target 注册表两处:`agent/sast_agent/config.py:91-111` 与
  `agent/run_baseline.py:66-87`(形状相同,手工同步)。
- D8 转译先例(jsp→java)的 `"pre"` 钩子仍留在
  `agent/sast_agent/pipeline.py:57-67`;jsp-legacy 本身已于 2026-09-05
  被移除(git 历史可考)。

## 2. 三档分层策略

按引擎可用性把语言分三档,每档对应不同接入路径:

- **档 1:双引擎支持**(现有 4 语言,以及 **PHP**)→ 走完整管线。
  PHP 的接入是纯集成工作,改动面已摸清(见 §6 附注),本文不展开。
- **档 2:仅 Semgrep**(Joern 无前端但 Semgrep 支持,如 Rust/Lua)→
  sink 检测仍由 Semgrep 规则承担,链分析/taint 确认走 §3 的降级路径。
- **档 3:均无**(Perl)→ 本文重点:agent-only 降级模式。

原则:档位是**每个 target 的显式配置**,不做自动探测(避免 `.sc` 那种
静默回落 js 的事故在 Python 侧重演)。

## 3. 降级模式(档 3)架构

核心思路:**把 Semgrep/Joern 从" backbone "降为"可选增强",LLM agent
层升为主力**。这与项目 2026-09-10 的方向(引擎侧工作停止,转向
LLM/agent 层)一致——D6 已证明:LLM 用 `search_code` 接力能覆盖引擎
盲区且不改变判决天花板。

组件盘点:

| 组件 | 现状依赖 | 降级模式下 | 工作类型 |
| --- | --- | --- | --- |
| repo map | tree-sitter,`scripts/repo_map.py` | 注册 perl 后直接用 | 需适配 |
| B 类 planner | 只消费 repo_map.json(`planner.py:115-118`) | 直接用 | 复用 |
| `search_code` / `read_function` | ripgrep / 磁盘 | 直接用 | 复用 |
| sink 检测 | Semgrep → `semgrep_to_sinks.py` | **自定义 Perl sink 扫描器** | 需新建 |
| CPG 构建 | `ensure_cpg`(pipeline.py:135) | 配置位关闭 | 需新建 |
| A 类链简报 | `get_chains` / `get_chain_snippets`(joern) | **无链 brief**:sink 记录 + grep 接力 | 需新建 |
| B 类 `get_forward_slice` | `extract_entrypoint_snippets.sc`(joern) | **no-joern fallback**(repo map 符号表 + import 图 + grep) | 需新建 |
| 证据引用解析 | `_REF_RE` ×3 | 扩展名加 `pl\|pm\|t` | 需适配 |
| judges / report 匹配 | `simple_name`、route label 匹配 | Perl 命名约定适配 | 需适配 |
| verifier/worker prompt | guard idiom 列表(`worker.py:102-105`) | 加 Perl 框架 idiom | 需适配 |

### 3.1 自定义 Perl sink 扫描器(替代 Semgrep)

- 形态:单文件 Python(stdlib only,与 `jsp_to_java.py` 的风格一致),
  regex/启发式规则表,逐文件扫描,输出**与 `semgrep_to_sinks.py:39-47`
  完全相同的 schema**:`{"file", "line", "rule", "vuln_type", "cwe"}`,
  rule id 约定 `pl-sink-<vuln_type>`。
- 接入点:`config.py` TARGETS 增加可选键 `sink_detector`(替代 `rules`);
  `run_semgrep` 阶段按 `engines.semgrep` 开关替换为调用该扫描器。
- Perl sink 词汇表(8 个 A 类,高度词汇化,适合 regex):
  - sqli:DBI `$dbh->do/prepare/selectall_arrayref/selectrow_array` 的字符串
    插值调用
  - cmdi:`system`/`exec`/qx(反引号)、`open($fh, "-|", $cmd)` 管道 open、
    `IPC::Open2/Open3`
  - path-traversal:2 参 `open($fh, "<", $path)`、动态 `require/do $file`
  - rce:字符串 `eval $code`
  - xss:CGI 上下文向 HTML `print` 未转义变量
  - deserialization:`Storable::thaw`、`YAML::Load`、Data::Dumper+eval 回路
  - xxe:`XML::LibXML` 未关 `expand_entities`、`XML::Simple`
  - ssti:Template Toolkit 对插值模板串 `process`
- **明确否决 Semgrep `--lang generic`**:无 AST、无语义,不比自写 regex
  强,还会制造"Semgrep 支持 Perl"的假象。

### 3.2 `engines` 配置位(pipeline 接线)

```python
# agent/sast_agent/config.py TARGETS 新增可选键(缺省 = 现状,全 True)
"perl-mojo": {
    "tree": "targets/perl-mojo",
    "ground_truth": "targets/perl-mojo/ground_truth.json",
    "engines": {"semgrep": False, "joern": False},
    "sink_detector": "scripts/perl_sinks.py",   # 替代 "rules"
}
```

- `engines.joern=False`:`ensure_cpg` 跳过;`get_chains`/`get_taint_flows`/
  `get_chain_snippets`/`list_entrypoints`/`get_forward_slice` 不挂载或返回
  降级提示(沿用 tools.py:48-50 的人工接力话术)。
- `engines.semgrep=False`:semgrep 阶段替换为 `sink_detector`。
- `run_baseline.py:66-87` 的 TARGETS 镜像同步;stage 接线按 `engines`
  条件化。

### 3.3 A 类无链 brief(investigator 降级)

现状:investigator 的简报来自 `get_chains`(sink→entrypoint 反向链)。
降级:种子 = sink 记录(file/line/rule)+ `read_function` 取所在 sub
全文 + `search_code` 找调用方逐跳接力(即今天 `joern_query` 失败后的
manual relay 路径,转为主路径)。LLM 判读的输入从"CPG 链 + 源码切片"
变为"sink 上下文 + grep 接力链",证据强度下降,见 §5。

### 3.4 `get_forward_slice` 的 no-joern fallback(B 类 worker)

worker 需要"handler + 下游 callee 源码"。降级实现:从 repo_map.json 取
handler 所在文件的符号表与 import 引用图,定位被调函数,`read_function`
取源,depth-1 展开;更深的钻取交给 LLM 用现有 read/search 工具动态完成
(planner 的假设队列本身已是 joern-free,不需要改)。定位为粗近似,不追求
CPG 精度。

### 3.5 repo_map.py 的 perl 注册

tree-sitter-language-pack 已自带 perl grammar(无需新依赖,平台 wheel
可用性待 spike 验证):

- `LANG_BY_EXT`(repo_map.py:36)加 `.pl/.pm/.t → "perl"`。
- 新增 `extract_perl`:`sub name {}` 函数、`package Foo::Bar`、路由形态
  —— Mojolicious 的 `$r->get('/path')`(member call)与 Dancer2 的
  `get '/path' => sub {}`(coderef 参数);CGI 风格无路由声明,按 **D9
  先例用文件名约定生成 route label**(`pages/X.pl` → `"/X.pl"`)。
  tree-sitter-perl 的具体节点名以 spike 实测为准。
- `resolve_import` 加 perl 分支(`use Foo::Bar` → `Foo/Bar.pm`,
  `require`)。
- `build_map` 分发加 perl 分支。

### 3.6 评分/报告适配(零碎但必须)

- `_REF_RE` 三处(report.py:413、investigator.py:173、worker.py:129)
  扩展名加 `pl|pm|t`。
- judges/`report.py` 的 `simple_name` 与 route label:Perl 没有 joern
  fullName,命名约定由自家 extractor 定义,保持 `文件::sub` 形态即可;
  CGI 模式走文件名 route(D9 先例)。
- verifier/worker prompt 的 guard idiom 列表加 Perl:CGI.pm 参数校验、
  Mojolicious `under`/hook、Dancer2 `hook before`。

## 4. 否决方案记录(防重复提出)

- **转译 Perl → 受支持语言**(复用 pipeline.py:57-67 的 `"pre"` 钩子):
  D8 的 jsp→java 能成,是因为 JSP 与 servlet Java 语义 1:1 对应;Perl 的
  sigil/标量-列表上下文/魔法变量与任何目标语言都不存在保持语义的映射,
  LLM 转译不可验证且会改变漏洞语义,破坏 benchmark 完整性。且 jsp-legacy
  本身已于 2026-09-05 被移除——转译路线在本 repo 已被实践否定。
- **自研 Joern Perl 前端**:人月级成本,benchmark 收益不匹配。
- **Semgrep `--lang generic`**:见 §3.1。
- **等上游**:Semgrep/Joern 均无 Perl roadmap 迹象。

## 5. 指标与期望管理

- 降级模式下 A 类证据 = "sink + grep 接力链",recall/置信度**预期低于
  全管线**,这是设计内损失,不是 bug。
- B 类几乎不受影响:planner 本就 joern-free,worker 的降级 slice 由 LLM
  动态钻取补足(D6 已验证该模式可达 recall 天花板)。
- 报告与 baseline 按 `engines` 档位分组呈现,**降级 target 的指标不与
  全管线 target 直接比较**;`run_baseline.py --compare` 按档分闸。

## 6. 实施路线(供下一轮参考,spike 优先)

1. **Spike:tree-sitter-perl 解析质量**——用贴近 benchmark 风格的 Perl
   样本(Mojolicious 路由 + DBI + CGI 习惯写法)实测解析率与节点形态;
   Perl 5 语法不可判定(indirect object syntax、here-doc),只需证明
   函数/路由提取 ~90% 可用。**此步决定 §3.5 可行性,先做。**
2. `repo_map.py` perl 注册(§3.5)。
3. `scripts/perl_sinks.py` sink 扫描器(§3.1)。
4. `engines` 配置位接线(§3.2)+ `run_baseline.py` 镜像。
5. investigator 无链 brief(§3.3)+ `get_forward_slice` fallback(§3.4)。
6. `targets/perl-mojo/`(建议 Mojolicious:路由显式、tree-sitter 友好;
   CGI 目录风格备选)+ `ground_truth.json`/`GROUND_TRUTH.md`,遵循
   AGENTS.md 变更协议(VULN:/SAFE: 标记、15 类分类法镜像)。
7. 评分适配(§3.6),baseline 冻结,报告标注档位。

风险标注:步骤 1 最大(决定整条路可行性);步骤 6 的 CGI 变体若选用,
需额外验证文件名 route 约定与 judge 匹配的兼容性(D9 机制可复用)。

---

附注:**PHP(档 1)接入清单**(留作未来,本文不实施):本机装 PHP
运行时 → `targets/php-<framework>/` + ground truth →
`analysis/rules/sinks-php.yml`(8 条规则,`languages: [php]`,沿用
`vuln_type`/`cwe` metadata 契约)→ `config.py` 与 `run_baseline.py`
注册 → **7 个 `.sc` 脚本各加 `.*\.php$` 分支(必须放在 `else "js"` 回落
之前)** + 4 处 sinkNames 表 + `taint_confirm.sc` 的 source regex
(`$_GET/$_POST/...`)→ `repo_map.py`/`repo_map.sc` 注册 → `_REF_RE`×3 →
judges 的 `simple_name` 适配 php2cpg fullName 形态。按 D5/D7 规律,
预算一次 php2cpg 前端 quirk 修复(动态调用空节点是已知候选)。
