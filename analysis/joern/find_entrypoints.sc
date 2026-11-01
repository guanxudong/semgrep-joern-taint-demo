// find_entrypoints.sc — enumerate HTTP entrypoints of the loaded CPG as JSON lines.
//
// Usage:
//   joern --script analysis/joern/find_entrypoints.sc <cpg.bin> [> entrypoints.jsonl]
//
// Works for all targets:
//   python-flask  : methods defined in routes|api/*.py (route path is best-effort)
//   java-spring   : methods with @GetMapping/@PostMapping/... annotations
//   js-ts-express : router.get/post/... call sites; handler is the <lambda>N via METHOD_REF
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Method

def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"")

def routeFromAttr(code: String): String =
  code.replaceAll("(?i)^@?(route|http(get|post|put|delete|patch)|[a-z]+mapping)\\(", "")
      .replaceAll("\\)$", "").replaceAll("\"", "")

val lang = if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"

// ---- registry dispatch entrypoints (non-HTTP targets, D17) — same logic
// as backward_from_sinks.sc, keep in sync ----
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

lang match {
  case "java" =>
    cpg.method.where(_.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping")).l.foreach { m =>
      val base = m.typeDecl.annotation.name("RequestMapping").code.headOption.map(routeFromAttr).getOrElse("")
      val subAnn = m.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping").headOption
      val sub = subAnn.map(a => routeFromAttr(a.code)).getOrElse("")
      val verb = subAnn.map(_.name.replace("Mapping", "").toUpperCase).getOrElse("?")
      println(s"""{"lang":"java","route":"$verb ${esc(base)}${esc(sub)}","method":"${esc(m.fullName)}","file":"${esc(m.file.name.headOption.getOrElse("?"))}","line":${m.lineNumber.getOrElse(-1)}}""")
    }
    // transpiled-JSP pages (D9): _jspService in generated pages/*_jsp.java;
    // route by filename convention (pages/X_jsp.java -> /X.jsp), no verb
    cpg.method.nameExact("_jspService").where(_.file.name(".*_jsp\\.java$")).l.foreach { m =>
      val base = m.file.name.headOption.getOrElse("?").replaceAll("^.*/", "").replaceAll("_jsp\\.java$", "")
      println(s"""{"lang":"java","route":"\\"/${esc(base)}.jsp\\"","method":"${esc(m.fullName)}","file":"${esc(m.file.name.headOption.getOrElse("?"))}","line":${m.lineNumber.getOrElse(-1)}}""")
    }

  case "python" =>
    cpg.file.name("(routes|api)/.*\\.py$").ast.isMethod
      .filter(m => m.fullName.matches("(routes|api)/[^:]+:<module>\\.[A-Za-z_][A-Za-z0-9_]*")).l
      .sortBy(m => (m.file.name.headOption.getOrElse(""), m.lineNumber.getOrElse(-1)))
      .foreach { m =>
        val route = m.annotation.code.headOption.getOrElse("?")
        println(s"""{"lang":"python","route":"${esc(route)}","method":"${esc(m.fullName)}","file":"${esc(m.file.name.headOption.getOrElse("?"))}","line":${m.lineNumber.getOrElse(-1)}}""")
      }

  case _ => // js / ts (Express)
    cpg.call.name("(?i)^(get|post|put|delete|patch)$").where(_.file.name("routes/.*")).l.foreach { c =>
      val route = c.argument(1).code.replaceAll("^'|'$|^\"|\"$", "")
      val handler = c.start.argument.isMethodRef.referencedMethod.l.headOption
      val mName = handler.map(_.fullName).getOrElse("?")
      val mLine = handler.flatMap(_.lineNumber).getOrElse(-1)
      println(s"""{"lang":"js","route":"${c.name.toUpperCase} ${esc(route)}","method":"${esc(mName)}","file":"${esc(c.file.name.headOption.getOrElse("?"))}","line":$mLine}""")
    }
}

// registry dispatch (non-HTTP targets): same entries as the HTTP table above
registryEntries.foreach { case (m, route) =>
  println(s"""{"lang":"$lang","route":"${esc(route)}","method":"${esc(m.fullName)}","file":"${esc(m.file.name.headOption.getOrElse("?"))}","line":${m.lineNumber.getOrElse(-1)}}""")
}
