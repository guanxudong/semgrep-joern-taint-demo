// taint_confirm.sc — for every Semgrep-reported sink, ask Joern's dataflow
// engine whether user-controlled input (Flask `request.*`) actually reaches
// the sink's dangerous argument. Sinks with a real flow are CONFIRMED;
// call-graph-reachable sinks without a data flow are UNCONFIRMED (suspected
// false positives of the "hardcoded/sanitized-at-source" kind).
//
// Usage:
//   SINKS_FILE=/tmp/sinks_py.json joern --script analysis/joern/taint_confirm.sc py_cpg.bin > /tmp/taint_py.jsonl
//
// Output: one JSON object per sink on stdout (JSON Lines):
//   {"sink": {"name","file","line","rule","vuln_type"},
//    "status": "CONFIRMED"|"UNCONFIRMED",
//    "flows": [{"source_method": "...",   // entrypoint attribution
//               "path": [{"file","line","code"}, ...]}, ...]}
// Diagnostics go to stderr.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import java.nio.file.{Files, Paths}

// Sink name table, aligned with analysis/rules/sinks-*.yml. Used both for
// default sink discovery and for name-first sink matching (see below), so it
// must also cover constructor sinks (`new Template`, `new FileInputStream`).
val sinkNames = Map(
  "python" -> "^(execute|executemany|system|popen|eval|exec|loads|load|render_template_string|from_string|fromstring|parse|parseString|XMLParser|send_file|open)$",
  "java"   -> "^(executeQuery|executeUpdate|execute|exec|eval|read|readObject|readAllBytes|readString|parse|start|Template|FileInputStream|FileReader)$",
  "js"     -> "^(query|execute|exec|execSync|spawn|spawnSync|eval|Function|readFileSync|readFile|createReadStream|parseXml|unserialize|deserialize|render|compile|send)$",
  "csharp" -> "^(ExecuteReader|ExecuteNonQuery|ExecuteScalar|Start|CompileAssemblyFromSource|ReadAllText|ReadAllBytes|OpenRead|Create|Load|LoadXml|Deserialize|RunCompile|Compile|Content)$"
)

val lang = if (cpg.file.name(".*\\.cs$").nonEmpty) "csharp"
           else if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"
val nameRe = sinkNames(lang)

// ---- taint sources ----
// Call-based sources: direct request-input accessor calls.
//   python: Flask `request.*` (also catches other frameworks' `request` objects)
//   js    : Express `req.*`; Koa `ctx.*` / `ctx.request.*`; Fastify/Hapi `request.*`
//   java  : HttpServletRequest accessors
//   csharp: HttpRequest accessors
val callSourceRe = lang match {
  case "python" => ".*request\\.(args|form|values|cookies|headers|json|data|get_data|get_json|view_args).*"
  case "js"     => ".*((req|ctx|request)\\.(query|body|params|headers|cookies|payload)|ctx\\.request\\.(body|query|headers)|req\\.param\\().*"
  case "java"   => ".*(getParameter|getHeader|getInputStream|getReader|getQueryString|getPathInfo|getCookies).*"
  case _        => ".*Request\\.(Query|Form|Body|Headers|RouteData|Cookies).*"
}
// Parameter-based sources: handlers that receive input as parameters instead
// of via accessor calls.
//   java   : Spring (@RequestParam/@RequestBody/@PathVariable/...) and JAX-RS
//            (@PathParam/@QueryParam/...) annotated parameters.
//   csharp : controller action params (csharpsrc2cpg models attributes poorly),
//            plus params of any [HttpGet]/...-annotated action (minimal APIs,
//            controllers outside a `Controllers/` dir).
//   python : route placeholders (`/<int:id>` Flask-style, `/{id}` FastAPI-style)
//            bind input to handler arguments without touching `request.*`.
//            pysrc2cpg has no ANNOTATION nodes for decorators — the route call
//            sits on the decorator line(s) right above the `def`, so the
//            handler is the next method defined after the route call's line.
//            (Django binds path params via URLconf — not covered.)
def sources = lang match {
  case "java" =>
    cpg.call.code(callSourceRe).cast[nodes.CfgNode] ++
    cpg.parameter.where(_.annotation.name(".*(RequestParam|RequestBody|RequestHeader|PathVariable|ModelAttribute|RequestPart|PathParam|QueryParam|FormParam|HeaderParam|BeanParam)")).cast[nodes.CfgNode]
  case "csharp" =>
    cpg.call.code(callSourceRe).cast[nodes.CfgNode] ++
    cpg.parameter.where(_.file.name(".*Controllers/.*")).cast[nodes.CfgNode] ++
    cpg.method.where(_.annotation.name("(?i).*Http(Get|Post|Put|Delete|Patch).*")).parameter.cast[nodes.CfgNode]
  case "python" =>
    val placeholderCalls = cpg.call.name("^(route|get|post|put|delete|patch|api_route)$")
      .where(_.argument.code(".*(<[^>]+>|[{][^{}]+[}]).*")).l
    val routeHandlers = placeholderCalls.flatMap { c =>
      c.file.ast.isMethod
        .filter(m => m.lineNumber.getOrElse(-1) > c.lineNumber.getOrElse(Int.MaxValue))
        .sortBy(_.lineNumber.getOrElse(-1)).l.headOption
    }
    cpg.call.code(callSourceRe).cast[nodes.CfgNode] ++
    routeHandlers.flatMap(_.parameter.l).cast[nodes.CfgNode]
  case _ =>
    cpg.call.code(callSourceRe).cast[nodes.CfgNode]
}

// ---- sink calls from SINKS_FILE (same matching as backward_from_sinks.sc) ----
// sink-name match: direct call name, or constructor sinks by type name
// (`<init>` methodFullName / `new X(...)` code), since several rules target
// constructors (e.g. `new Template(...)`, `new FileInputStream(...)`).
// methodFullName carries a `:signature` suffix — strip it before taking the
// simple name. Kind ranking: name (0) < methodFullName (1) < code (2), so an
// actual sink call beats an operator whose code merely mentions `new X(...)`.
def simpleNameOf(mfn: String): String = {
  val noSig = mfn.split(":").headOption.getOrElse(mfn)
  noSig.split("\\.").toList.filter(_.nonEmpty).reverse
    .dropWhile(n => n == "<init>" || n == "<clinit>").headOption.getOrElse(noSig)
}
def sinkNameKind(c: nodes.Call): Int =
  if (c.name.matches(nameRe)) 0
  else if (simpleNameOf(c.methodFullName).matches(nameRe)) 1
  else if ("\\bnew\\s+([A-Za-z_][A-Za-z0-9_]*)".r.findFirstMatchIn(c.code).exists(_.group(1).matches(nameRe))) 2
  else 3

val sinkCalls: List[(nodes.Call, Map[String, String])] = {
  val f = sys.env.getOrElse("SINKS_FILE", "")
  val text = Files.readString(Paths.get(f))
  val entries = "\\{[^{}]+\\}".r.findAllIn(text).flatMap { obj =>
    for {
      file <- "\"file\"\\s*:\\s*\"([^\"]+)\"".r.findFirstMatchIn(obj).map(_.group(1))
      line <- "\"line\"\\s*:\\s*(\\d+)".r.findFirstMatchIn(obj).map(_.group(1).toInt)
    } yield {
      val meta = Map(
        "rule"      -> "\"rule\"\\s*:\\s*\"([^\"]+)\"".r.findFirstMatchIn(obj).map(_.group(1)).getOrElse(""),
        "vuln_type" -> "\"vuln_type\"\\s*:\\s*\"([^\"]+)\"".r.findFirstMatchIn(obj).map(_.group(1)).getOrElse("")
      )
      (file, line, meta)
    }
  }.toList
  // Within a ±window window around the Semgrep line hint, prefer the candidate
  // call whose NAME matches the sink table (nearest to the hint wins); only
  // fall back to nearest-line when no name matches in the window.
  val window = 3
  val found = entries.flatMap { case (file, line, meta) =>
    val cands = cpg.call.filter(c => c.file.name.headOption.exists(_.endsWith(file)))
      .filter(c => math.abs(c.lineNumber.getOrElse(-1) - line) <= window).l
    def dist(c: nodes.Call): Int = math.abs(c.lineNumber.getOrElse(-1) - line)
    val named = cands.map(c => c -> sinkNameKind(c)).filter(_._2 < 3)
      .sortBy { case (c, k) => (dist(c), k, c.lineNumber.getOrElse(-1)) }.map(_._1)
    val pick = if (named.nonEmpty) named.take(1)
               else cands.sortBy(c => (dist(c), -c.code.length)).take(1)
    pick.map(_ -> meta)
  }.distinct
  System.err.println(s"// SINKS_FILE=$f: ${entries.size} semgrep findings -> ${found.size} CPG call nodes matched")
  found
}

// ---- minimal JSON string escaping ----
def esc(s: String): String = s.flatMap {
  case '"'  => "\\\""
  case '\\' => "\\\\"
  case '\n' => "\\n"
  case '\r' => "\\r"
  case '\t' => "\\t"
  case c    => c.toString
}
def q(s: String): String = "\"" + esc(s) + "\""

// index methods by (file, line range) for flow-source attribution;
// innermost (smallest) containing method wins, so module-level <module> loses
val methodIndex = cpg.method.l.flatMap { m =>
  for { f <- m.file.name.headOption; s <- m.lineNumber; e <- m.lineNumberEnd } yield (f, s, e, m.fullName)
}.sortBy { case (_, s, e, _) => e - s }
def methodOf(file: String, line: Int): String =
  methodIndex.collectFirst { case (f, s, e, fn) if f == file && s <= line && line <= e => fn }.getOrElse("?")

// Express route handlers are anonymous lambdas; resolve "<lambda>N" to the
// registering route call (e.g. "GET /users/search") for readable attribution.
def attributeSource(file: String, line: Int): String = {
  val fn = methodOf(file, line)
  if (!fn.contains("<lambda>")) return fn
  val route = cpg.methodRef.where(_.referencedMethod.fullNameExact(fn)).l.headOption.flatMap { mr =>
    mr.start.astParent.l.collectFirst { case c: nodes.Call => s"${c.name.toUpperCase} ${c.argument(1).code}" }
  }
  route.map(r => s"$fn [$r]").getOrElse(fn)
}

sinkCalls.foreach { case (s, meta) =>
  val file = s.file.name.headOption.getOrElse("?")
  val line = s.lineNumber.getOrElse(-1)

  // dataflow: can any request.* source reach any argument of this sink call?
  val flows = s.argument.reachableByFlows(sources).l

  // dedup identical paths; cap at 3 flows per entrypoint (not per sink), so
  // duplicate paths from one route cannot crowd out distinct routes
  val seen = scala.collection.mutable.Set.empty[String]
  val perEntry = scala.collection.mutable.Map.empty[String, Int].withDefaultValue(0)
  val flowsJson = flows.flatMap { path =>
    val elems = path.elements.l.collect { case n: nodes.AstNode => n }
    val sig = elems.map(e => s"${e.file.name.headOption.getOrElse("?")}:${e.lineNumber.getOrElse(-1)}").mkString("|")
    val srcMethod = elems.headOption.map(e => attributeSource(e.file.name.headOption.getOrElse("?"), e.lineNumber.getOrElse(-1))).getOrElse("?")
    if (elems.isEmpty || seen.contains(sig) || perEntry(srcMethod) >= 3) None
    else {
      seen += sig
      perEntry(srcMethod) = perEntry(srcMethod) + 1
      val pathJson = elems.map { e =>
        s"""{"file":${q(e.file.name.headOption.getOrElse("?"))},"line":${e.lineNumber.getOrElse(-1)},"code":${q(e.code.take(200))}}"""
      }.mkString(",")
      Some(s"""{"source_method":${q(srcMethod)},"path":[$pathJson]}""")
    }
  }.mkString(",")

  val status = if (flows.nonEmpty) "CONFIRMED" else "UNCONFIRMED"
  println(s"""{"sink":{"name":${q(s.name)},"file":${q(file)},"line":$line,"rule":${q(meta("rule"))},"vuln_type":${q(meta("vuln_type"))}},"status":"$status","flows":[$flowsJson]}""")
}
System.err.println(s"// total sinks: ${sinkCalls.size}")
