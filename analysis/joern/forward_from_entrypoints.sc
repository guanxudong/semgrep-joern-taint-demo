// forward_from_entrypoints.sc — for every HTTP entrypoint, walk the call graph
// FORWARD (caller -> callee -> ...) down to the leaves, marking known sinks.
//
// Usage:
//   joern --script analysis/joern/forward_from_entrypoints.sc <cpg.bin>
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Method

val sinkNames = Map(
  "python" -> "^(execute|executemany|system|popen|eval|exec|loads|load|render_template_string|from_string|fromstring|parse|parseString|XMLParser|send_file|open)$",
  "java"   -> "^(executeQuery|executeUpdate|execute|exec|eval|read|readObject|readAllBytes|readString|parse|start|Template|FileInputStream|FileReader|print)$",
  "js"     -> "^(query|execute|exec|execSync|spawn|spawnSync|eval|Function|readFileSync|readFile|createReadStream|parseXml|unserialize|deserialize|render|compile|send)$"
)

val lang = if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"
val nameRe = sinkNames(lang)

// ---- registry dispatch entrypoints (non-HTTP targets, D17) — copied
// verbatim from backward_from_sinks.sc, keep in sync ----
def resolveHandler(arg: io.shiftleft.codepropertygraph.generated.nodes.Expression): Option[Method] =
  arg.start.isMethodRef.referencedMethod.l.headOption.orElse {
    "[A-Za-z_][A-Za-z0-9_]*$".r.findFirstMatchIn(arg.code.trim).map(_.group(0))
      .flatMap(n => cpg.method.nameExact(n).l.headOption)
  }

val registryEntries: List[(Method, String)] = lang match {
  case "java" =>
    cpg.call.nameExact("register").l.flatMap { c =>
      val key = c.argument(1).code.trim.replaceAll("^\"|\"$", "")
      resolveHandler(c.argument(2)).map(_ -> s"CMD $key")
    }
  case "python" =>
    cpg.call.nameExact("subscribe").l.flatMap { c =>
      val subj = c.argument(1).code.trim.replaceAll("^'|'$|^\"|\"$", "")
      resolveHandler(c.argument(2)).map(_ -> s"MSG $subj")
    } ++ cpg.call.nameExact("watch").l.flatMap { c =>
      resolveHandler(c.argument(2)).map(_ -> s"FILE ${c.argument(1).code.trim}")
    }
  case _ => Nil
}

// ---- transpiled-JSP entrypoints (D9): pages/X_jsp.java::_jspService ----
// (see backward_from_sinks.sc for the route-label convention)
val jspEntrypoints: List[(String, String)] =
  if (lang != "java") List.empty
  else cpg.method.nameExact("_jspService").where(_.file.name(".*_jsp\\.java$")).l.map { m =>
    val base = m.file.name.headOption.getOrElse("?").replaceAll("^.*/", "").replaceAll("_jsp\\.java$", "")
    m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} \"/$base.jsp\""
  }

// ---- entrypoints (same detection as find_entrypoints.sc) ----
val entrypoints: List[(String, String)] = (lang match {
  case "java" =>
    cpg.method.where(_.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping")).l.map { m =>
      val ann = m.annotation.name(".*Mapping").code.headOption.getOrElse("")
      m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} $ann"
    } ++ jspEntrypoints
  case "python" =>
    cpg.file.name("(routes|api)/.*\\.py$").ast.isMethod
      .filter(m => m.fullName.matches("(routes|api)/[^:]+:<module>\\.[A-Za-z_][A-Za-z0-9_]*")).l
      .map(m => m.fullName -> m.fullName)
  case _ =>
    cpg.call.name("(?i)^(get|post|put|delete|patch)$").where(_.file.name("routes/.*")).l.flatMap { c =>
      c.start.argument.isMethodRef.referencedMethod.l.headOption.map { h =>
        h.fullName -> s"${c.name.toUpperCase} ${c.argument(1).code}"
      }
    }
}) ++ registryEntries.map { case (m, r) => m.fullName -> r }

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
