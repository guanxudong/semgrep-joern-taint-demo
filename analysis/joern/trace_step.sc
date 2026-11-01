// trace_step.sc — execute ONE structured trace directive from the tracer
// state machine (agent/sast_agent/trace_engine.py) and print JSON rows.
//
// The LLM never writes joern/Scala: it picks a `kind` from a closed menu
// plus a symbol/file, the orchestrator writes a directive JSON, and this
// script is the only translator. One JVM launch per directive.
//
// Usage:
//   DIRECTIVE_FILE=/tmp/directive.json joern --script analysis/joern/trace_step.sc <cpg.bin>
//
// DIRECTIVE_FILE: {"kind": "...", "symbol": "...", "file": "...", "line": N}
//   kind = callers_of | writes_to | reads_of | find_call_sites
//        | trace_back | methods_in_file
//
// Output: one JSON object per row on stdout (diagnostics to stderr):
//   callers_of(symbol)      {"method","name","file","line","line_end"}
//                             — enclosing-method rows for every caller
//   find_call_sites(name)   {"method","file","line","line_end","code",
//                            "receiver"} — name-based call-site candidates
//                             (over-approximate recall; the LLM disambiguates)
//   writes_to(symbol)       {"method","file","line","line_end","code"}
//   reads_of(symbol)        {"method","file","line","line_end","code"}
//   methods_in_file(file)   {"method","name","file","line","line_end"}
//   trace_back(methodFullName) {"route","entrypoint","path":[fullName,...]}
//                             — backward BFS from an arbitrary method,
//                               same entrypoint table + D5/D7 repairs as
//                               backward_from_sinks.sc
//
// TODO(M9.0): entrypoint detection, the JS ghost-callee repair (D5), the
// C# source-text caller fallback (D7) and esc/q are copied from
// backward_from_sinks.sc — commonize into a shared prelude.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.codepropertygraph.generated.nodes.Method
import java.nio.file.{Files, Paths}

// ---- minimal JSON ----
def esc(s: String): String = s.flatMap {
  case '"'  => "\\\""
  case '\\' => "\\\\"
  case '\n' => "\\n"
  case '\r' => "\\r"
  case '\t' => "\\t"
  case c    => c.toString
}
def q(s: String): String = "\"" + esc(s) + "\""

// ---- directive parsing (regex extraction; the file is orchestrator-written
// and flat, so a full JSON parser dependency is not worth it) ----
val directiveText = Files.readString(Paths.get(sys.env("DIRECTIVE_FILE")))
def dstr(key: String): String =
  ("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").r.findFirstMatchIn(directiveText)
    .map(_.group(1)).getOrElse("")
val kind   = dstr("kind")
val symbol = dstr("symbol")
val argFile = dstr("file")

// ---- language detection (same as backward_from_sinks.sc) ----
val lang = if (cpg.file.name(".*\\.cs$").nonEmpty) "csharp"
           else if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"

// ---- entrypoint table (copy of backward_from_sinks.sc; needed by
// trace_back and by callers_of rows so the LLM can see "this caller IS an
// entrypoint" without a second query) ----
val jspEntrypoints: Map[String, String] =
  if (lang != "java") Map.empty
  else cpg.method.nameExact("_jspService").where(_.file.name(".*_jsp\\.java$")).l.map { m =>
    val base = m.file.name.headOption.getOrElse("?").replaceAll("^.*/", "").replaceAll("_jsp\\.java$", "")
    m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} \"/$base.jsp\""
  }.toMap

val entrypoints: Map[String, String] = lang match {
  case "csharp" =>
    cpg.method.where(_.annotation.name("(?i).*Http(Get|Post|Put|Delete|Patch).*")).l.map { m =>
      val base = m.typeDecl.annotation.name("Route").code.headOption.getOrElse("")
      val sub = m.annotation.name("(?i).*Http.*").code.headOption.getOrElse("")
      m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} $base $sub"
    }.toMap
  case "java" =>
    (cpg.method.where(_.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping")).l.map { m =>
      val ann = m.annotation.name(".*Mapping").code.headOption.getOrElse("")
      m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} $ann"
    } ++ jspEntrypoints).toMap
  case "python" =>
    cpg.file.name("(routes|api)/.*\\.py$").ast.isMethod
      .filter(m => m.fullName.matches("(routes|api)/[^:]+:<module>\\.[A-Za-z_][A-Za-z0-9_]*")).l
      .map(m => m.fullName -> m.fullName).toMap
  case _ =>
    cpg.call.name("(?i)^(get|post|put|delete|patch)$").where(_.file.name("routes/.*")).l.flatMap { c =>
      c.start.argument.isMethodRef.referencedMethod.l.headOption.map { h =>
        h.fullName -> s"${c.name.toUpperCase} ${c.argument(1).code}"
      }
    }.toMap
}

// ---- JS ghost-callee repair (D5, copied from backward_from_sinks.sc) ----
def resolveModule(importerFile: String, entity: String): String = {
  val parts = importerFile.split("/").toList.dropRight(1) ++
    entity.split("/").toList.filter(p => p.nonEmpty && p != ".")
  val out = scala.collection.mutable.ListBuffer.empty[String]
  parts.foreach {
    case ".." => if (out.nonEmpty) out.remove(out.size - 1)
    case p    => out += p
  }
  out.mkString("/")
}

val jsImportMap: Map[String, Map[String, String]] =
  if (lang != "js") Map.empty
  else cpg.file.name(".*\\.(js|ts)$").l.flatMap { f =>
    f.ast.isImport.l.flatMap { i =>
      for (as <- i.importedAs; ent <- i.importedEntity)
        yield (f.name, as -> resolveModule(f.name, ent))
    }
  }.groupBy(_._1).map { case (f, rows) => f -> rows.map(_._2).toMap }

def fileMatchesModule(file: String, mod: String): Boolean =
  file == mod + ".js" || file == mod + ".ts" ||
  file == mod + "/index.js" || file == mod + "/index.ts"

val ghostCallerPairs: List[(String, Method)] =
  if (lang != "js") List.empty
  else (for {
    m  <- cpg.method.where(_.file.name(".+")).l
    mf <- m.file.name.headOption.toList
    c  <- cpg.call.nameExact(m.name).where(_.callee.isExternal).l
    cf <- c.file.name.headOption.toList
    recv <- ("^([A-Za-z_$][A-Za-z0-9_$]*)\\." + java.util.regex.Pattern.quote(m.name) + "\\b").r
      .findFirstMatchIn(c.code.trim).map(_.group(1)).toList
    mod <- jsImportMap.getOrElse(cf, Map.empty).get(recv).toList
    if fileMatchesModule(mf, mod)
  } yield m.fullName -> c.method)

val ghostCallersByName: Map[String, List[Method]] =
  ghostCallerPairs.groupBy(_._1).map { case (k, vs) => k -> vs.map(_._2).distinct }
    .withDefault(_ => Nil)

// ---- C# missing-inner-call fallback (D7, LOW_CONFIDENCE, copied) ----
val srcRoot = Paths.get(sys.env.getOrElse("SRC_ROOT", "."))
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

val csTextCallerCache = scala.collection.mutable.Map.empty[String, List[Method]]
def textCallers(m: Method): List[Method] =
  if (lang != "csharp") Nil
  else csTextCallerCache.getOrElseUpdate(m.fullName, {
    val svcType = m.typeDecl.name.headOption.getOrElse("")
    if (svcType.isEmpty) Nil
    else {
      val pat = ("\\." + java.util.regex.Pattern.quote(m.name) + "\\s*\\(").r
      cpg.method.where(_.file.name("Controllers/.*\\.cs$")).l.filter { cand =>
        cand.fullName != m.fullName &&
        pat.findFirstIn(methodText(cand)).nonEmpty &&
        cand.typeDecl.member.exists(_.typeFullName.split('.').last == svcType)
      }.map { cand =>
        System.err.println(s"// D7 LOW_CONFIDENCE edge: ${cand.fullName} -> ${m.fullName}")
        cand
      }
    }
  })
def methodText(m: Method): String = methodSource(m)

def allCallers(m: Method): List[Method] =
  (m.caller.l ++ ghostCallersByName(m.fullName) ++ textCallers(m)).distinct

// ---- row emitters ----
def methodRow(m: Method): String = {
  val f = m.file.name.headOption.getOrElse("?")
  val ep = entrypoints.get(m.fullName).map(r => s""","route":${q(r)}""").getOrElse("")
  s"""{"method":${q(m.fullName)},"name":${q(m.name)},"file":${q(f)},"line":${m.lineNumber.getOrElse(-1)},"line_end":${m.lineNumberEnd.getOrElse(-1)}$ep}"""
}

def siteRow(file: String, line: Int, code: String, m: Method): String = {
  val ep = entrypoints.get(m.fullName).map(r => s""","route":${q(r)}""").getOrElse("")
  s"""{"method":${q(m.fullName)},"file":${q(file)},"line":$line,"line_end":${m.lineNumberEnd.getOrElse(-1)},"method_line":${m.lineNumber.getOrElse(-1)},"code":${q(code.take(200))}$ep}"""
}

kind match {

  case "callers_of" =>
    var ms = cpg.method.nameExact(symbol).l
    if (ms.isEmpty)
      ms = cpg.method.name(".*" + java.util.regex.Pattern.quote(symbol) + ".*").l
    val rows = ms.flatMap(allCallers).distinct
    if (rows.nonEmpty) {
      rows.take(50).foreach(m => println(methodRow(m)))
    } else {
      // No call-graph callers: the symbol is likely registered as a VALUE
      // (registry/dict/callback — `HANDLERS = {"diag": f}`), which is an
      // identifier reference, not a call. Fall back to reference sites so
      // the LLM sees the registration and can chase the registry object
      // (reads_of) to the dispatch site. Baked-in playbook: recall is the
      // engine's job, disambiguation the LLM's.
      val refs = cpg.identifier.nameExact(symbol).l.flatMap { i =>
        i.file.name.headOption.map { f =>
          siteRow(f, i.lineNumber.getOrElse(-1),
                  i.code + "  (reference, not a call)", i.method)
        }
      }.distinct
      refs.take(50).foreach(println)
      System.err.println(s"// callers_of($symbol): no callers; ${refs.size} reference sites")
    }
    System.err.println(s"// callers_of($symbol): ${rows.size} caller rows")

  case "find_call_sites" =>
    var cs = cpg.call.nameExact(symbol).l
    if (cs.isEmpty)
      cs = cpg.call.name(".*" + java.util.regex.Pattern.quote(symbol) + ".*").l
    val callRows = cs.flatMap { c =>
      val recv = "([A-Za-z_$][A-Za-z0-9_$]*)\\.".r.findFirstMatchIn(c.code.trim)
        .map(_.group(1)).getOrElse("")
      c.file.name.headOption.map { f =>
        siteRow(f, c.lineNumber.getOrElse(-1), c.code, c.method)
          .stripSuffix("}") + s""","receiver":${q(recv)}}"""
      }
    }
    // Registry/callback registrations (`HANDLERS = {"diag": run_diag}`,
    // `subscribe("x", fn)`) reference the function as an IDENTIFIER, not a
    // call — include them or the recall misses dynamic dispatch entirely.
    val identRows = cpg.identifier.nameExact(symbol).l.flatMap { i =>
      i.file.name.headOption.map { f =>
        siteRow(f, i.lineNumber.getOrElse(-1), i.code + "  (reference)",
                i.method)
      }
    }
    val rows = (callRows ++ identRows).distinct
    rows.take(50).foreach(println)
    System.err.println(s"// find_call_sites($symbol): ${rows.size} rows")

  case "writes_to" =>
    val rows = cpg.assignment.l.filter { a =>
      val t = a.target.code
      t == symbol || t.endsWith("." + symbol)
    }.flatMap { a =>
      a.file.name.headOption.map(f => siteRow(f, a.lineNumber.getOrElse(-1), a.code, a.method))
    }
    rows.take(50).foreach(println)
    System.err.println(s"// writes_to($symbol): ${rows.size} rows")

  case "reads_of" =>
    val rows = cpg.identifier.nameExact(symbol).l.filter { i =>
      i.astParent match {
        case c: nodes.Call =>
          !(c.name == "<operator>.assignment" && c.argument(1).code == symbol)
        case _ => true
      }
    }.flatMap { i =>
      i.file.name.headOption.map(f => siteRow(f, i.lineNumber.getOrElse(-1), i.code, i.method))
    }
    rows.take(50).foreach(println)
    System.err.println(s"// reads_of($symbol): ${rows.size} rows")

  case "methods_in_file" =>
    val rows = cpg.method.l.filter { m =>
      m.file.name.headOption.exists(f => f == argFile || f.endsWith("/" + argFile))
    }
    rows.take(50).foreach(m => println(methodRow(m)))
    System.err.println(s"// methods_in_file($argFile): ${rows.size} rows")

  case "trace_back" =>
    val starts = cpg.method.fullNameExact(symbol).l ++
      cpg.method.nameExact(symbol).l
    val maxDepth = 8
    starts.foreach { start =>
      var results = List.empty[List[Method]]
      var queue = List(List(start))
      while (queue.nonEmpty) {
        val path = queue.head; queue = queue.tail
        val cur = path.head
        if (entrypoints.contains(cur.fullName)) {
          results ::= path
        } else if (path.size <= maxDepth) {
          allCallers(cur).foreach { caller =>
            if (!path.exists(_.fullName == caller.fullName)) queue :+= caller :: path
          }
        }
      }
      results.take(10).foreach { chain =>
        val route = entrypoints(chain.head.fullName)
        println(s"""{"route":${q(route)},"entrypoint":${q(chain.head.fullName)},"path":[${chain.map(m => q(m.fullName)).mkString(",")}]}""")
      }
      if (results.isEmpty)
        System.err.println(s"// trace_back($symbol): no chain to any entrypoint")
    }
    if (starts.isEmpty)
      System.err.println(s"// trace_back($symbol): method not found in CPG")

  case other =>
    System.err.println(s"// unknown directive kind: $other")
    System.exit(2)
}
