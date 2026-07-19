// find_entrypoints.sc — enumerate HTTP entrypoints of the loaded CPG as JSON lines.
//
// Usage:
//   joern --script analysis/joern/find_entrypoints.sc <cpg.bin> [> entrypoints.jsonl]
//
// Works for all four targets:
//   python-flask  : methods defined in routes/*.py (route path is best-effort)
//   java-spring   : methods with @GetMapping/@PostMapping/... annotations
//   js-ts-express : router.get/post/... call sites; handler is the <lambda>N via METHOD_REF
//   csharp-aspnet : methods with [HttpGet]/[HttpPost]/... attributes
import io.shiftleft.semanticcpg.language._

def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"")

def routeFromAttr(code: String): String =
  code.replaceAll("(?i)^@?(route|http(get|post|put|delete|patch)|[a-z]+mapping)\\(", "")
      .replaceAll("\\)$", "").replaceAll("\"", "")

val lang = if (cpg.file.name(".*\\.cs$").nonEmpty) "csharp"
           else if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"

lang match {
  case "csharp" =>
    cpg.method.where(_.annotation.name("(?i).*Http(Get|Post|Put|Delete|Patch).*")).l.foreach { m =>
      val cls = m.typeDecl.name.headOption.getOrElse("?")
      val base = m.typeDecl.annotation.name("Route").code.headOption.map(routeFromAttr).getOrElse("")
      val sub = m.annotation.name("(?i).*Http.*").code.headOption.map(routeFromAttr).getOrElse("")
      val verb = m.annotation.name("(?i).*Http(Get|Post|Put|Delete|Patch).*").name.headOption
        .getOrElse("Http").replace("Http", "").toUpperCase
      println(s"""{"lang":"csharp","route":"$verb /${esc(base)}/${esc(sub)}","method":"${esc(m.fullName)}","file":"${esc(m.file.name.headOption.getOrElse("?"))}","line":${m.lineNumber.getOrElse(-1)}}""")
    }

  case "java" =>
    cpg.method.where(_.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping")).l.foreach { m =>
      val base = m.typeDecl.annotation.name("RequestMapping").code.headOption.map(routeFromAttr).getOrElse("")
      val subAnn = m.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping").headOption
      val sub = subAnn.map(a => routeFromAttr(a.code)).getOrElse("")
      val verb = subAnn.map(_.name.replace("Mapping", "").toUpperCase).getOrElse("?")
      println(s"""{"lang":"java","route":"$verb ${esc(base)}${esc(sub)}","method":"${esc(m.fullName)}","file":"${esc(m.file.name.headOption.getOrElse("?"))}","line":${m.lineNumber.getOrElse(-1)}}""")
    }

  case "python" =>
    cpg.file.name("routes/.*\\.py$").ast.isMethod
      .filter(m => m.fullName.matches("routes/[^:]+:<module>\\.[A-Za-z_][A-Za-z0-9_]*")).l
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
