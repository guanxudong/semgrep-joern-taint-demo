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
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Method
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
val sinkCalls = sys.env.get("SINKS_FILE").filter(_.nonEmpty) match {
  case Some(f) =>
    val text = Files.readString(Paths.get(f))
    val entries = "\\{[^{}]+\\}".r.findAllIn(text).flatMap { obj =>
      for {
        file <- "\"file\"\\s*:\\s*\"([^\"]+)\"".r.findFirstMatchIn(obj).map(_.group(1))
        line <- "\"line\"\\s*:\\s*(\\d+)".r.findFirstMatchIn(obj).map(_.group(1).toInt)
      } yield (file, line)
    }.toList
    val found = entries.flatMap { case (file, line) =>
      val cands = cpg.call.filter(c => c.file.name.headOption.exists(_.endsWith(file)))
        .filter(c => math.abs(c.lineNumber.getOrElse(-1) - line) <= 1).l
      val named = cands.filter(c => c.name.matches(nameRe))
      // prefer the call that matches the sink name table; otherwise the outermost call on that line
      if (named.nonEmpty) named else cands.sortBy(c => -c.code.length).take(1)
    }.distinct
    println(s"// SINKS_FILE=$f: ${entries.size} semgrep findings -> ${found.size} CPG call nodes matched")
    found
  case None =>
    cpg.call.name(nameRe).l
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

sinkCalls.foreach { s =>
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
}
println(s"\n// total sinks: ${sinkCalls.size}, entrypoints: ${entrypoints.size}")
