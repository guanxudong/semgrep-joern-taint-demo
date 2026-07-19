// forward_from_entrypoints.sc — for every HTTP entrypoint, walk the call graph
// FORWARD (caller -> callee -> ...) down to the leaves, marking known sinks.
//
// Usage:
//   joern --script analysis/joern/forward_from_entrypoints.sc <cpg.bin>
import io.shiftleft.semanticcpg.language._

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

// ---- entrypoints (same detection as find_entrypoints.sc) ----
val entrypoints: List[(String, String)] = lang match {
  case "csharp" =>
    cpg.method.where(_.annotation.name("(?i).*Http(Get|Post|Put|Delete|Patch).*")).l.map { m =>
      val base = m.typeDecl.annotation.name("Route").code.headOption.getOrElse("")
      val sub = m.annotation.name("(?i).*Http.*").code.headOption.getOrElse("")
      m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} $base $sub"
    }
  case "java" =>
    cpg.method.where(_.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping")).l.map { m =>
      val ann = m.annotation.name(".*Mapping").code.headOption.getOrElse("")
      m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} $ann"
    }
  case "python" =>
    cpg.file.name("routes/.*\\.py$").ast.isMethod
      .filter(m => m.fullName.matches("routes/[^:]+:<module>\\.[A-Za-z_][A-Za-z0-9_]*")).l
      .map(m => m.fullName -> m.fullName)
  case _ =>
    cpg.call.name("(?i)^(get|post|put|delete|patch)$").where(_.file.name("routes/.*")).l.flatMap { c =>
      c.start.argument.isMethodRef.referencedMethod.l.headOption.map { h =>
        h.fullName -> s"${c.name.toUpperCase} ${c.argument(1).code}"
      }
    }
}

// ---- forward BFS (indent = call depth) ----
def forward(rootFullName: String, maxDepth: Int = 6): Unit = {
  var visited = Set.empty[String]
  var queue = List((rootFullName, 0))
  while (queue.nonEmpty) {
    val (fn, depth) = queue.head; queue = queue.tail
    if (depth <= maxDepth && !visited.contains(fn)) {
      visited += fn
      cpg.method.fullNameExact(fn).l.headOption.foreach { m =>
        val sinksHere = m.call.name(nameRe).l
          .map(c => s"${c.name}@${c.lineNumber.getOrElse(-1)}").distinct
        val tag = if (sinksHere.nonEmpty) "  => SINK " + sinksHere.mkString(", ") else ""
        val file = m.file.name.headOption.getOrElse("?")
        println("  " * depth + s"${m.name}  ($file)$tag")
        queue :++= m.call.callee.filterNot(_.isExternal).l.map(_.fullName -> (depth + 1))
      }
    }
  }
}

entrypoints.sortBy(_._2).foreach { case (fn, route) =>
  println(s"\n=== ENTRYPOINT $route")
  println(s"    ($fn)")
  forward(fn)
}
println(s"\n// total entrypoints: ${entrypoints.size}")
