// backward_from_sinks.sc — for every sink call, walk the call graph BACKWARD
// (callee -> caller -> ... ) until an HTTP entrypoint is reached.
//
// Usage:
//   # sinks straight from the CPG (built-in sink name table):
//   joern --script analysis/joern/backward_from_sinks.sc <cpg.bin>
//
//   # sinks taken from Semgrep (converted by scripts/semgrep_to_sinks.py):
//   SINKS_FILE=sinks_py.json joern --script analysis/joern/backward_from_sinks.sc py_cpg.bin
//
// SINKS_FILE format: JSON array of {"file": "...", "line": N, "rule": "...", ...}
// with file paths relative to the directory that was given to joern-parse.
//
// Set CHAINS_JSON=<path> to additionally write one JSON line per sink with its
// entrypoint chains (consumed by scripts/chain_report.py):
//   {"sink":{"name","file","line","rule","vuln_type"},
//    "chains":[{"route","entrypoint","path":[fullName, ...]}, ...]}
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Method
import java.nio.file.{Files, Paths}

// Sink name table, aligned with analysis/rules/sinks-*.yml (keep in sync with
// taint_confirm.sc / forward_from_entrypoints.sc). Must also cover constructor
// sinks (`new Template`, `new FileInputStream`) for name-first matching.
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

// ---- sink calls: from SINKS_FILE if given, else by name table ----
// sink-name match: direct call name, or constructor sinks by type name
// (`<init>` methodFullName / `new X(...)` code). Keep in sync with taint_confirm.sc.
// methodFullName carries a `:signature` suffix — strip it before taking the
// simple name. Kind ranking: name (0) < methodFullName (1) < code (2).
def simpleNameOf(mfn: String): String = {
  val noSig = mfn.split(":").headOption.getOrElse(mfn)
  noSig.split("\\.").toList.filter(_.nonEmpty).reverse
    .dropWhile(n => n == "<init>" || n == "<clinit>").headOption.getOrElse(noSig)
}
def sinkNameKind(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Int =
  if (c.name.matches(nameRe)) 0
  else if (simpleNameOf(c.methodFullName).matches(nameRe)) 1
  else if ("\\bnew\\s+([A-Za-z_][A-Za-z0-9_]*)".r.findFirstMatchIn(c.code).exists(_.group(1).matches(nameRe))) 2
  else 3

val sinkCalls: List[(io.shiftleft.codepropertygraph.generated.nodes.Call, Map[String, String])] = sys.env.get("SINKS_FILE").filter(_.nonEmpty) match {
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
    // Within a ±window window around the Semgrep line hint, prefer the candidate
    // call whose NAME matches the sink table (nearest to the hint wins); only
    // fall back to nearest-line when no name matches in the window.
    val window = 3
    val found = entries.flatMap { case (file, line, meta) =>
      val cands = cpg.call.filter(c => c.file.name.headOption.exists(_.endsWith(file)))
        .filter(c => math.abs(c.lineNumber.getOrElse(-1) - line) <= window).l
      def dist(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Int = math.abs(c.lineNumber.getOrElse(-1) - line)
      val named = cands.map(c => c -> sinkNameKind(c)).filter(_._2 < 3)
        .sortBy { case (c, k) => (dist(c), k, c.lineNumber.getOrElse(-1)) }.map(_._1)
      val pick = if (named.nonEmpty) named.take(1)
                 else cands.sortBy(c => (dist(c), -c.code.length)).take(1)
      pick.map(_ -> meta)
    }.distinct
    println(s"// SINKS_FILE=$f: ${entries.size} semgrep findings -> ${found.size} CPG call nodes matched")
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

// Optional machine-readable output: set CHAINS_JSON=<path> to also write one
// JSON line per sink with its entrypoint chains (consumed by chain_report.py):
//   {"sink":{"name","file","line","rule","vuln_type"},
//    "chains":[{"route","entrypoint","path":[fullName, ...]}, ...]}
val chainsOut = sys.env.get("CHAINS_JSON").filter(_.nonEmpty)
  .map(p => new java.io.PrintWriter(Files.newBufferedWriter(Paths.get(p))))

sinkCalls.foreach { case (s, meta) =>
  val file = s.file.name.headOption.getOrElse("?")
  val line = s.lineNumber.getOrElse(-1)
  val inMethod = s.method.fullName
  println(s"\n=== SINK ${s.name}  @ $file:$line  (in $inMethod)")
  if (entrypoints.contains(inMethod)) {
    println(s"  SHALLOW: sink is inside the entrypoint itself -> ${entrypoints(inMethod)}")
  }
  val chains = backward(s)
  if (chains.isEmpty && !entrypoints.contains(inMethod)) {
    println("  (no call-chain to any entrypoint found within depth limit)")
  }
  chains.foreach { chain =>
    val route = entrypoints(chain.head.fullName)
    println(s"  -> $route")
    chain.foreach { m =>
      println(s"       ${m.fullName}")
    }
  }
  chainsOut.foreach { w =>
    // a sink inside an entrypoint is a chain of length 1 (the SHALLOW case)
    val allChains = (if (entrypoints.contains(inMethod)) List(List(s.method)) else List.empty) ++ chains
    val chainsJson = allChains.map { chain =>
      val route = entrypoints(chain.head.fullName)
      s"""{"route":${q(route)},"entrypoint":${q(chain.head.fullName)},"path":[${chain.map(m => q(m.fullName)).mkString(",")}]}"""
    }.mkString(",")
    w.println(s"""{"sink":{"name":${q(s.name)},"file":${q(file)},"line":$line,"rule":${q(meta("rule"))},"vuln_type":${q(meta("vuln_type"))}},"chains":[$chainsJson]}""")
    w.flush()
  }
}
chainsOut.foreach(_.close())
println(s"\n// total sinks: ${sinkCalls.size}, entrypoints: ${entrypoints.size}")
