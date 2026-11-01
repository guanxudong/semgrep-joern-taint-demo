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

val sinkNames = Map(
  "python" -> "^(execute|executemany|system|popen|eval|exec|loads|load|render_template_string|from_string|fromstring|parseString|open)$",
  "java"   -> "^(executeQuery|executeUpdate|execute|exec|eval|readObject|readAllBytes|readString|parse|start|print)$",
  "js"     -> "^(query|execute|exec|execSync|spawn|eval|Function|readFileSync|readFile|parseXml|unserialize|render|compile|send)$"
)

val lang = if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"
val nameRe = sinkNames(lang)

// ---- registry dispatch entrypoints (non-HTTP targets, D17) ----
// router.register("KEY", obj::handler) -> "CMD KEY"; bus.subscribe("subj", fn)
// -> "MSG subj"; watcher.watch(dir, fn) -> "FILE dir". Scorers match on
// file+function, so the route label only needs to carry the registry key.
// No such call shapes exist in the web targets (verified), so this is a
// no-op there. (Copied verbatim from backward_from_sinks.sc — keep in sync.)
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
val jspEntrypoints: Map[String, String] =
  if (lang != "java") Map.empty
  else cpg.method.nameExact("_jspService").where(_.file.name(".*_jsp\\.java$")).l.map { m =>
    val base = m.file.name.headOption.getOrElse("?").replaceAll("^.*/", "").replaceAll("_jsp\\.java$", "")
    m.fullName -> s"${m.typeDecl.name.headOption.getOrElse("?")} \"/$base.jsp\""
  }.toMap

// ---- entrypoint method fullNames (same detection as find_entrypoints.sc) ----
val entrypoints: Map[String, String] = (lang match {
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
}) ++ registryEntries.map { case (m, r) => m.fullName -> r }.toMap

// ---- JS ghost-callee repair (D5) — see backward_from_sinks.sc ----
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

// ---- sink calls: (call node, optional semgrep metadata) ----
// Sink matching aligned with backward_from_sinks.sc / taint_confirm.sc
// (M9.0-lite: replpp has no cross-file import, so the block is copied
// verbatim — keep the three files in sync): name-first within a ±3 window
// with kind ranking (name < methodFullName < `new X(...)` code), so
// constructor sinks (`new Template`, `new FileInputStream`) and off-by-one
// Semgrep line hints pick the same node in every script.
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
        val window = 3
        val cands = cpg.call.filter(c => c.file.name.headOption.exists(_.endsWith(file)))
          .filter(c => math.abs(c.lineNumber.getOrElse(-1) - line) <= window).l
        def dist(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Int = math.abs(c.lineNumber.getOrElse(-1) - line)
        val named = cands.map(c => c -> sinkNameKind(c)).filter(_._2 < 3)
          .sortBy { case (c, k) => (dist(c), k, c.lineNumber.getOrElse(-1)) }.map(_._1)
        val pick = if (named.nonEmpty) named.take(1)
                   else cands.sortBy(c => (dist(c), -c.code.length)).take(1)
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
      (cur.caller.l ++ ghostCallersByName(cur.fullName)).foreach { caller =>
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
