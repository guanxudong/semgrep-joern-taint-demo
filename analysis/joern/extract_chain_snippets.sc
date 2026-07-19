// extract_chain_snippets.sc — for every sink, walk the call graph BACKWARD to
// its HTTP entrypoints (same logic as backward_from_sinks.sc), then dump the
// SOURCE CODE of every method on each chain as JSON lines (one object per sink).
//
// Usage:
//   SINKS_FILE=/tmp/sinks_py.json joern --script analysis/joern/extract_chain_snippets.sc py_cpg.bin > /tmp/snippets_py.jsonl
//
// Each output line is a self-contained JSON object:
//   {"sink": {"name","file","line","in_method","rule","vuln_type"},
//    "chains": [{"entrypoint": "...", "calls": ["...", ...]}],
//    "snippets": [{"function","file","start_line","end_line","code"}, ...]}
// `snippets` is the de-duplicated union of all methods on all chains for that
// sink — ready to hand to an LLM for review.
//
// Method source comes from the CPG's `code` property when the frontend fills
// it in; otherwise it is sliced from disk by line range. SRC_ROOT must then
// point at the directory that was given to joern-parse (default: ".").
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Method
import java.nio.file.{Files, Paths}

val srcRoot = Paths.get(sys.env.getOrElse("SRC_ROOT", "."))

// read a method's source: CPG code property, falling back to a disk slice
def methodSource(m: Method): String = {
  if (m.code != null && m.code.nonEmpty && m.code != "<empty>") return m.code
  (m.file.name.headOption, m.lineNumber, m.lineNumberEnd) match {
    case (Some(f), Some(start), Some(end)) =>
      try {
        val lines = Files.readAllLines(srcRoot.resolve(f))
        lines.subList(math.max(start - 1, 0), math.min(end, lines.size))
          .toArray.mkString("\n")
      } catch { case _: Exception => "" }
    case _ => ""
  }
}

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

// ---- entrypoint method fullNames (same detection as find_entrypoints.sc) ----
val entrypoints: Map[String, String] = lang match {
  case "csharp" =>
    cpg.method.where(_.annotation.name("(?i).*Http(Get|Post|Put|Delete|Patch).*")).l.map { m =>
      val base = m.typeDecl.annotation.name("Route").code.headOption.getOrElse("")
      val sub = m.annotation.name("(?i).*Http.*").code.headOption.getOrElse("")
      m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} $base $sub"
    }.toMap
  case "java" =>
    cpg.method.where(_.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping")).l.map { m =>
      val ann = m.annotation.name(".*Mapping").code.headOption.getOrElse("")
      m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} $ann"
    }.toMap
  case "python" =>
    cpg.file.name("routes/.*\\.py$").ast.isMethod
      .filter(m => m.fullName.matches("routes/[^:]+:<module>\\.[A-Za-z_][A-Za-z0-9_]*")).l
      .map(m => m.fullName -> m.fullName).toMap
  case _ =>
    cpg.call.name("(?i)^(get|post|put|delete|patch)$").where(_.file.name("routes/.*")).l.flatMap { c =>
      c.start.argument.isMethodRef.referencedMethod.l.headOption.map { h =>
        h.fullName -> s"${c.name.toUpperCase} ${c.argument(1).code}"
      }
    }.toMap
}

// ---- sink calls: (call node, optional semgrep metadata) ----
val sinkCalls: List[(io.shiftleft.codepropertygraph.generated.nodes.Call, Map[String, String])] =
  sys.env.get("SINKS_FILE").filter(_.nonEmpty) match {
    case Some(f) =>
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
    case None =>
      cpg.call.name(nameRe).l.map(_ -> Map("rule" -> "", "vuln_type" -> ""))
  }

// ---- backward BFS over the call graph ----
def backward(sinkCall: io.shiftleft.codepropertygraph.generated.nodes.Call, maxDepth: Int = 8): List[List[Method]] = {
  var results = List.empty[List[Method]]
  var queue = List(List(sinkCall.method))
  while (queue.nonEmpty) {
    val path = queue.head; queue = queue.tail
    val cur = path.head
    if (entrypoints.contains(cur.fullName)) {
      results ::= path
    } else if (path.size <= maxDepth) {
      cur.caller.l.foreach { caller =>
        if (!path.exists(_.fullName == caller.fullName)) queue :+= caller :: path
      }
    }
  }
  results
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

sinkCalls.foreach { case (s, meta) =>
  val file = s.file.name.headOption.getOrElse("?")
  val line = s.lineNumber.getOrElse(-1)
  val inMethod = s.method.fullName
  val chains = backward(s)

  // de-duplicated union of every method on every chain (sink's own method included)
  val methods = scala.collection.mutable.LinkedHashMap.empty[String, Method]
  methods(inMethod) = s.method
  chains.flatten.foreach(m => methods.getOrElseUpdate(m.fullName, m))

  val chainsJson = chains.map { chain =>
    val route = entrypoints(chain.head.fullName)
    s"""{"entrypoint":${q(route)},"calls":[${chain.map(m => q(m.fullName)).mkString(",")}]}"""
  }.mkString(",")

  val snippetsJson = methods.values.map { m =>
    val f = m.file.name.headOption.getOrElse("?")
    val start = m.lineNumber.getOrElse(-1)
    val end = m.lineNumberEnd.getOrElse(-1)
    s"""{"function":${q(m.fullName)},"file":${q(f)},"start_line":$start,"end_line":$end,"code":${q(methodSource(m))}}"""
  }.mkString(",")

  println(s"""{"sink":{"name":${q(s.name)},"file":${q(file)},"line":$line,"in_method":${q(inMethod)},"rule":${q(meta("rule"))},"vuln_type":${q(meta("vuln_type"))}},"chains":[$chainsJson],"snippets":[$snippetsJson]}""")
}
System.err.println(s"// total sinks: ${sinkCalls.size}, entrypoints: ${entrypoints.size}")
