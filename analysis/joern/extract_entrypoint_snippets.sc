// extract_entrypoint_snippets.sc — for EVERY HTTP entrypoint of the loaded
// CPG, walk the call graph FORWARD (caller -> callee, internal methods only,
// BFS depth <= 5, cap ~15 methods) and dump the entrypoint plus the SOURCE
// CODE of every collected method as one JSON line per entrypoint.
//
// Usage:
//   SRC_ROOT=targets/python-flask joern --script analysis/joern/extract_entrypoint_snippets.sc py_cpg.bin > /tmp/ep_snippets_py.jsonl
//
// Each output line is a self-contained JSON object:
//   {"entrypoint": {"route":"...","method":"<fullName>","file":"...","line":N},
//    "callees": ["<fullName>", ...],
//    "snippets": [{"function","file","start_line","end_line","code"}, ...]}
// `snippets` is the de-duplicated source of the entrypoint method (always
// first) plus all collected callees — ready to hand to an LLM for semantic
// review of the non-sink (category-B) vulnerability classes.
//
// Entrypoint detection is the SAME per-language logic as find_entrypoints.sc:
//   java:   @GetMapping/@PostMapping/... annotations  route: "VERB base/sub"
//   python: methods in routes|api/*.py                route: raw annotation code (best-effort)
//   js/ts:  router.get/post/... calls in routes/.*    route: "VERB /path"
//
// Method source comes from whichever is LONGER: a disk slice by line
// range (SRC_ROOT must then point at the directory that was given to
// joern-parse, default: ".") or the CPG's `code` property — javasrc2cpg
// fills `code` with only the signature line.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Method
import java.nio.file.{Files, Paths}

val srcRoot = Paths.get(sys.env.getOrElse("SRC_ROOT", "."))

// read a method's source: prefer a disk slice by line range when it is
// LONGER than the CPG code property — javasrc2cpg fills `code` with just
// the signature line, which would hide the whole method body from the LLM
def methodSource(m: Method): String = {
  val cpgCode =
    if (m.code != null && m.code.nonEmpty && m.code != "<empty>") m.code else ""
  (m.file.name.headOption, m.lineNumber, m.lineNumberEnd) match {
    case (Some(f), Some(start), Some(end)) if end > start =>
      try {
        val lines = Files.readAllLines(srcRoot.resolve(f))
        val sliced = lines.subList(math.max(start - 1, 0), math.min(end, lines.size))
          .toArray.mkString("\n")
        if (sliced.length > cpgCode.length) sliced else cpgCode
      } catch { case _: Exception => cpgCode }
    case _ => cpgCode
  }
}

val lang = if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"

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

// strip @(Route|HttpGet|...Mapping)("...") wrappers down to the raw path
def routeFromAttr(code: String): String =
  code.replaceAll("(?i)^@?(route|http(get|post|put|delete|patch)|[a-z]+mapping)\\(", "")
      .replaceAll("\\)$", "").replaceAll("\"", "")

// ---- entrypoints: (method fullName, route label) — same detection as find_entrypoints.sc ----
val entrypoints: List[(String, String)] = (lang match {
  case "java" =>
    cpg.method.where(_.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping")).l.map { m =>
      val base = m.typeDecl.annotation.name("RequestMapping").code.headOption.map(routeFromAttr).getOrElse("")
      val subAnn = m.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping").headOption
      val sub = subAnn.map(a => routeFromAttr(a.code)).getOrElse("")
      val verb = subAnn.map(_.name.replace("Mapping", "").toUpperCase).getOrElse("?")
      m.fullName -> s"$verb $base$sub"
    } ++
    // transpiled-JSP pages (D9): _jspService in generated pages/*_jsp.java;
    // route by filename convention (pages/X_jsp.java -> /X.jsp), no verb
    cpg.method.nameExact("_jspService").where(_.file.name(".*_jsp\\.java$")).l.map { m =>
      val base = m.file.name.headOption.getOrElse("?").replaceAll("^.*/", "").replaceAll("_jsp\\.java$", "")
      m.fullName -> s"\"/$base.jsp\""
    }
  case "python" =>
    cpg.file.name("(routes|api)/.*\\.py$").ast.isMethod
      .filter(m => m.fullName.matches("(routes|api)/[^:]+:<module>\\.[A-Za-z_][A-Za-z0-9_]*")).l
      .sortBy(m => (m.file.name.headOption.getOrElse(""), m.lineNumber.getOrElse(-1)))
      .map { m =>
        // pysrc2cpg carries no decorator annotations; keep the raw code as
        // find_entrypoints.sc does (route is best-effort; scoring matches on
        // file+function instead)
        m.fullName -> m.annotation.code.headOption.getOrElse(m.fullName)
      }
  case _ => // js / ts (Express): router.get/post/... call sites, handler via METHOD_REF
    cpg.call.name("(?i)^(get|post|put|delete|patch)$").where(_.file.name("routes/.*")).l.flatMap { c =>
      c.start.argument.isMethodRef.referencedMethod.l.headOption.map { h =>
        val route = c.argument(1).code.replaceAll("^'|'$|^\"|\"$", "")
        h.fullName -> s"${c.name.toUpperCase} $route"
      }
    }
}) ++ registryEntries.map { case (m, r) => m.fullName -> r }

// ---- forward BFS over the call graph (caller -> callee, internal only) ----
def forwardCallees(root: Method, maxDepth: Int = 5, maxMethods: Int = 15): List[Method] = {
  var visited = Set(root.fullName)
  var ordered = List.empty[Method]
  var queue = List(root -> 0)
  while (queue.nonEmpty && ordered.size < maxMethods) {
    val (cur, depth) = queue.head; queue = queue.tail
    ordered :+= cur
    if (depth < maxDepth) {
      cur.call.callee.filterNot(_.isExternal).l.foreach { callee =>
        if (!visited.contains(callee.fullName) && ordered.size + queue.size < maxMethods) {
          visited += callee.fullName
          queue :+= callee -> (depth + 1)
        }
      }
    }
  }
  ordered
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

val methodByFullName = cpg.method.l.map(m => m.fullName -> m).toMap
var n = 0
entrypoints.foreach { case (fn, route) =>
  methodByFullName.get(fn).foreach { m =>
    n += 1
    val methods = forwardCallees(m)
    val file = m.file.name.headOption.getOrElse("?")
    val line = m.lineNumber.getOrElse(-1)
    val calleesJson = methods.tail.map(x => q(x.fullName)).mkString(",")
    val snippetsJson = methods.map { x =>
      val f = x.file.name.headOption.getOrElse("?")
      val start = x.lineNumber.getOrElse(-1)
      val end = x.lineNumberEnd.getOrElse(-1)
      s"""{"function":${q(x.fullName)},"file":${q(f)},"start_line":$start,"end_line":$end,"code":${q(methodSource(x))}}"""
    }.mkString(",")
    println(s"""{"entrypoint":{"route":${q(route)},"method":${q(fn)},"file":${q(file)},"line":$line},"callees":[$calleesJson],"snippets":[$snippetsJson]}""")
  }
}
System.err.println(s"// total entrypoints: $n (lang=$lang)")
