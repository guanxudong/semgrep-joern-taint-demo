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

val sinkNames = Map(
  "python" -> "^(execute|executemany|system|popen|eval|exec|loads|load|render_template_string|from_string|fromstring|parseString|open)$",
  "java"   -> "^(executeQuery|executeUpdate|execute|exec|eval|readObject|readAllBytes|readString|parse|start)$",
  "js"     -> "^(query|execute|exec|execSync|spawn|eval|Function|readFileSync|readFile|parseXml|unserialize|render|compile|send)$",
  "csharp" -> "^(ExecuteReader|ExecuteNonQuery|ExecuteScalar|Start|CompileAssemblyFromSource|ReadAllText|ReadAllBytes|OpenRead|Create|Load|LoadXml|Deserialize|RunCompile|Compile|Content)$"
)

val lang = if (cpg.file.name(".*\\.cs$").nonEmpty) "csharp"
           else if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"
val nameRe = sinkNames(lang)

// ---- taint sources ----
// Call-based sources: direct request-input accessor calls (python/js verified).
val callSourceRe = lang match {
  case "python" => ".*request\\.(args|form|values|cookies|headers|json|data|get_data).*"
  case "js"     => ".*req\\.(query|body|params|headers|cookies).*"
  case "java"   => ".*(getParameter|getHeader|getInputStream|getReader|getQueryString).*"
  case _        => ".*Request\\.(Query|Form|Body|Headers|RouteData).*"
}
// Parameter-based sources: Spring/ASP.NET receive input as annotated action-method
// parameters (e.g. @RequestParam, [FromQuery]), not as accessor calls.
def sources = lang match {
  case "java" =>
    cpg.call.code(callSourceRe).cast[nodes.CfgNode] ++
    cpg.parameter.where(_.annotation.name(".*(RequestParam|RequestBody|RequestHeader|PathVariable)")).cast[nodes.CfgNode]
  case "csharp" =>
    // csharpsrc2cpg models attributes poorly; fall back to all controller action params
    cpg.call.code(callSourceRe).cast[nodes.CfgNode] ++
    cpg.parameter.where(_.file.name(".*Controllers/.*")).cast[nodes.CfgNode]
  case _ =>
    cpg.call.code(callSourceRe).cast[nodes.CfgNode]
}

// ---- sink calls from SINKS_FILE (same matching as backward_from_sinks.sc) ----
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
  val found = entries.flatMap { case (file, line, meta) =>
    val cands = cpg.call.filter(c => c.file.name.headOption.exists(_.endsWith(file)))
      .filter(c => math.abs(c.lineNumber.getOrElse(-1) - line) <= 1).l
    val named = cands.filter(c => c.name.matches(nameRe))
    // prefer the call that matches the sink name table; otherwise the outermost call on that line
    val pick = if (named.nonEmpty) named else cands.sortBy(c => -c.code.length).take(1)
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

  // de-duplicate identical paths, cap at 5 flows per sink
  val seen = scala.collection.mutable.Set.empty[String]
  val flowsJson = flows.flatMap { path =>
    val elems = path.elements.l.collect { case n: nodes.AstNode => n }
    val sig = elems.map(e => s"${e.file.name.headOption.getOrElse("?")}:${e.lineNumber.getOrElse(-1)}").mkString("|")
    if (elems.isEmpty || seen.contains(sig)) None
    else {
      seen += sig
      val srcMethod = elems.headOption.map(e => attributeSource(e.file.name.headOption.getOrElse("?"), e.lineNumber.getOrElse(-1))).getOrElse("?")
      val pathJson = elems.map { e =>
        s"""{"file":${q(e.file.name.headOption.getOrElse("?"))},"line":${e.lineNumber.getOrElse(-1)},"code":${q(e.code.take(200))}}"""
      }.mkString(",")
      Some(s"""{"source_method":${q(srcMethod)},"path":[$pathJson]}""")
    }
  }.take(5).mkString(",")

  val status = if (flows.nonEmpty) "CONFIRMED" else "UNCONFIRMED"
  println(s"""{"sink":{"name":${q(s.name)},"file":${q(file)},"line":$line,"rule":${q(meta("rule"))},"vuln_type":${q(meta("vuln_type"))}},"status":"$status","flows":[$flowsJson]}""")
}
System.err.println(s"// total sinks: ${sinkCalls.size}")
