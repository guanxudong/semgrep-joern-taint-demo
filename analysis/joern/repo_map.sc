// repo_map.sc — derive a "repo map" from the loaded CPG and print it as ONE
// JSON object on stdout (schema shared with the tree-sitter implementation):
//
//   {"root": "<SRC_ROOT>", "tool": "joern",
//    "files": [{"path","role","language","imports":[...],
//               "symbols":[{"kind","name","signature","line","parent"}],
//               "routes":[{"method","path","function","line"}]}],
//    "references": [{"from","to"}]}
//
// Usage:
//   SRC_ROOT=targets/python-flask joern --script analysis/joern/repo_map.sc py_cpg.bin > /tmp/repo_map_b_py.json
//
// - role: path heuristic (route/controller/service/data/config/util/test, else "other")
// - language: by extension (python/javascript/typescript/java/csharp)
// - symbols: per-language cleaning — python drops <module>/<body>/<fakeNew>/
//   <metaClassCallHandler> pseudo-methods (parent = class name for Class.m);
//   js/ts drops :program and <lambda>N from the symbol list; anonymous
//   route handlers get stable path-derived names via deriveName()
//   (mirrors the tree-sitter implementation).
//   java/cs drop <init>/<clinit>, cs also drops get_X/set_X property accessors.
//   Signatures come from the CPG where present (java/cs); for python and js/ts
//   the CPG signature is empty so one is synthesized from parameter names.
// - routes: same entrypoint detection as find_entrypoints.sc /
//   extract_entrypoint_snippets.sc, plus path-prefix resolution:
//   python: flask decorator CALL nodes (`bp.route("/x", methods=[...])`) +
//           the file's Blueprint(url_prefix="...") call; handler = the
//           module-level function defined right below the decorator line.
//   js/ts:  router.get/post/... call sites + mount prefix from
//           `app.use('/prefix', router)` resolved through the import table.
//   java:   @GetMapping/... + @RequestMapping base. csharp: [HttpGet]/... +
//           [Route] base.
// - references: file-level call edges (caller file -> callee file, internal
//   callees only, self-edges dropped). For python and js/ts, calls whose
//   receiver resolves through the file's import table add an edge even when
//   the frontend failed to link the callee (jssrc2cpg ghost calls, D5).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Method
import scala.collection.mutable.LinkedHashMap

val srcRoot = sys.env.getOrElse("SRC_ROOT", ".")

val lang = if (cpg.file.name(".*\\.cs$").nonEmpty) "csharp"
           else if (cpg.file.name(".*\\.java$").nonEmpty) "java"
           else if (cpg.file.name(".*\\.py$").nonEmpty) "python"
           else "js"

val allFiles = cpg.file.name.l.filter(n => n != "N/A" && n != "<unknown>").distinct.sorted
val fileSet = allFiles.toSet

def languageOf(path: String): String = path.split('.').last match {
  case "py"   => "python"
  case "js"   => "javascript"
  case "ts"   => "typescript"
  case "java" => "java"
  case "cs"   => "csharp"
  case _      => "unknown"
}

def roleOf(path: String): String = {
  val p = path.toLowerCase
  if (p.contains("test")) "test"
  else if (p.contains("routes/")) "route"
  else if (p.contains("controllers/")) "controller"
  else if (p.contains("services/")) "service"
  else if (p.contains("data/") || p.contains("db/")) "data"
  else if (p.contains("config")) "config"
  else if (p.contains("util")) "util"
  else "other"
}

// ---- minimal JSON (stable key order via LinkedHashMap) ----
def esc(s: String): String = s.flatMap {
  case '"'  => "\\\""
  case '\\' => "\\\\"
  case '\n' => "\\n"
  case '\r' => "\\r"
  case '\t' => "\\t"
  case c    => c.toString
}
def writeJson(v: Any, ind: Int): String = {
  val pad  = "  " * ind
  val pad2 = "  " * (ind + 1)
  v match {
    case null          => "null"
    case None          => "null"
    case Some(x)       => writeJson(x, ind)
    case s: String     => "\"" + esc(s) + "\""
    case i: Int        => i.toString
    case m: LinkedHashMap[_, _] =>
      if (m.isEmpty) "{}"
      else m.map { case (k, x) => pad2 + "\"" + esc(k.toString) + "\": " + writeJson(x, ind + 1) }
             .mkString("{\n", ",\n", "\n" + pad + "}")
    case xs: List[_] =>
      if (xs.isEmpty) "[]"
      else xs.map(x => pad2 + writeJson(x, ind + 1)).mkString("[\n", ",\n", "\n" + pad + "]")
    case other => "\"" + esc(other.toString) + "\""
  }
}
def obj(kvs: (String, Any)*): LinkedHashMap[String, Any] = LinkedHashMap(kvs: _*)

// ---- symbols ----
def synthSig(m: Method): String =
  if (m.signature != null && m.signature.nonEmpty) m.signature
  else {
    val params = m.parameter.l
      .filter(p => p.name != "self" && p.name != "this" && !p.name.startsWith("<"))
      .sortBy(_.index).map(_.name)
    s"${m.name}(${params.mkString(", ")})"
  }

def methodsOf(f: String): List[Method] =
  cpg.method.filterNot(_.isExternal).where(_.file.nameExact(f)).l

def symbolsOf(f: String): List[LinkedHashMap[String, Any]] = lang match {
  case "python" =>
    val pfx = s"$f:<module>."
    val topFns = scala.collection.mutable.ListBuffer.empty[Method]
    val clsMethods = scala.collection.mutable.ListBuffer.empty[(String, Method)]
    methodsOf(f).foreach { m =>
      if (m.fullName.startsWith(pfx)) {
        m.fullName.stripPrefix(pfx).split("\\.", -1).toList match {
          case simple :: Nil if !simple.contains("<") => topFns += m
          case cls :: name :: Nil if !cls.contains("<") && !name.contains("<") => clsMethods += ((cls, m))
          case _ =>
        }
      }
    }
    val classes = clsMethods.groupBy(_._1).map { case (cls, ms) =>
      val line = ms.map(_._2).filter(_.name == "<body>").flatMap(_.lineNumber).headOption
        .orElse(ms.flatMap(_._2.lineNumber).sorted.headOption).getOrElse(-1)
      obj("kind" -> "class", "name" -> cls, "signature" -> s"class $cls", "line" -> line, "parent" -> None)
    }
    val fns = topFns.map(m => obj("kind" -> "function", "name" -> m.name,
      "signature" -> synthSig(m), "line" -> m.lineNumber.getOrElse(-1), "parent" -> None))
    val ms = clsMethods.map { case (cls, m) => obj("kind" -> "method", "name" -> m.name,
      "signature" -> synthSig(m), "line" -> m.lineNumber.getOrElse(-1), "parent" -> Some(cls)) }
    (classes.toList ++ fns ++ ms).sortBy(_("line").asInstanceOf[Int])

  case "js" =>
    methodsOf(f)
      .filter(m => m.name != ":program" && !m.name.startsWith("<lambda>"))
      .map(m => obj("kind" -> "function", "name" -> m.name,
        "signature" -> synthSig(m), "line" -> m.lineNumber.getOrElse(-1), "parent" -> None))
      .sortBy(_("line").asInstanceOf[Int])

  case _ => // java / csharp: real typeDecls + their methods
    val skip = (m: Method) =>
      m.name == "<init>" || m.name == "<clinit>" || m.name.startsWith("<lambda>") ||
      (lang == "csharp" && m.name.matches("^(get|set)_[A-Z].*"))
    val classes = cpg.typeDecl.where(_.file.nameExact(f)).l
      .filter(t => !t.name.startsWith("<") && t.name != "ANY")
      .map(t => obj("kind" -> "class", "name" -> t.name,
        "signature" -> s"class ${t.name}", "line" -> t.lineNumber.getOrElse(-1), "parent" -> None))
    val ms = methodsOf(f).filterNot(skip).map { m =>
      val parent = m.typeDecl.l.headOption.filter(t => !t.name.startsWith("<")).map(_.name)
      obj("kind" -> "method", "name" -> m.name,
        "signature" -> synthSig(m), "line" -> m.lineNumber.getOrElse(-1), "parent" -> parent)
    }
    (classes ++ ms).sortBy(_("line").asInstanceOf[Int])
}

// ---- routes: (file, method, path, function, line) ----
def stripQuotes(s: String): String = s.replaceAll("^'|'$|^\"|\"$", "")

// stable name for anonymous route handlers, derived from the route path
// (mirrors the tree-sitter implementation's derive_handler_name)
def deriveName(path: String): String = {
  val segs = path.split("/").filter(s => s.nonEmpty && !s.startsWith(":"))
  if (segs.isEmpty) "handler"
  else {
    val parts = segs.last.split("[-_]").filter(_.nonEmpty)
    if (parts.isEmpty) "handler"
    else parts.head + parts.tail.map(p => p.take(1).toUpperCase + p.drop(1)).mkString
  }
}

def routeFromAttr(code: String): String =
  code.replaceAll("(?i)^@?(route|http(get|post|put|delete|patch)|[a-z]+mapping)\\(", "")
      .replaceAll("\\)$", "").replaceAll("\"", "")

val routes: List[(String, String, String, String, Int)] = lang match {
  case "python" =>
    // blueprint url_prefix per file: Blueprint("users", __name__, url_prefix = "/users")
    val bpPrefix = cpg.call.nameExact("Blueprint").l.flatMap { c =>
      c.file.name.headOption.map { f =>
        f -> "url_prefix\\s*=\\s*\"([^\"]*)\"".r.findFirstMatchIn(c.code).map(_.group(1)).getOrElse("")
      }
    }.toMap.withDefaultValue("")
    val topFn = methodsOf _ andThen (ms => ms.filter(m =>
      m.fullName.matches(".*:<module>\\.[A-Za-z_][A-Za-z0-9_]*")))
    cpg.call.nameExact("route").where(_.file.name("routes/.*\\.py$")).l.flatMap { c =>
      for {
        f <- c.file.name.headOption
        cline <- c.lineNumber
        handler <- topFn(f).filter(_.lineNumber.exists(_ > cline)).sortBy(_.lineNumber).headOption
      } yield {
        val verb = "methods\\s*=\\s*\\[\\s*\"([A-Z]+)\"".r.findFirstMatchIn(c.code)
          .map(_.group(1)).getOrElse("GET")
        val path = c.argument.argumentIndex(1).l.headOption.map(a => stripQuotes(a.code)).getOrElse("?")
        (f, verb, bpPrefix(f) + path, handler.name, handler.lineNumber.getOrElse(cline))
      }
    }

  case "js" =>
    // import table: file -> (importedAs -> importedEntity)
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
    def fileMatchesModule(file: String, mod: String): Boolean =
      file == mod + ".js" || file == mod + ".ts" ||
      file == mod + "/index.js" || file == mod + "/index.ts"
    val importMap: Map[String, Map[String, String]] = allFiles.flatMap { f =>
      cpg.file.nameExact(f).ast.isImport.l.flatMap { i =>
        for (as <- i.importedAs; ent <- i.importedEntity) yield (f, as -> ent)
      }
    }.groupBy(_._1).map { case (f, rows) => f -> rows.map(_._2).toMap }
    // mount prefixes: app.use('/users', usersRouter) -> routes/users.js
    val mountPrefix: Map[String, String] = cpg.call.nameExact("use").l.flatMap { c =>
      for {
        f <- c.file.name.headOption
        a1 <- c.argument.argumentIndex(1).l.headOption.map(_.code) if a1.matches("^['\"]/.+")
        a2 <- c.argument.argumentIndex(2).l.headOption.map(_.code)
        ent <- importMap.getOrElse(f, Map.empty).get(a2)
        target <- allFiles.find(fileMatchesModule(_, resolveModule(f, ent)))
      } yield target -> stripQuotes(a1)
    }.toMap.withDefaultValue("")
    cpg.call.name("(?i)^(get|post|put|delete|patch)$").where(_.file.name("routes/.*")).l.flatMap { c =>
      c.start.argument.isMethodRef.referencedMethod.l.headOption.flatMap { h =>
        c.file.name.headOption.map { f =>
          val path = c.argument.argumentIndex(1).l.headOption.map(a => stripQuotes(a.code)).getOrElse("?")
          val hname = if (h.name.startsWith("<lambda>")) deriveName(path) else h.name
          (f, c.name.toUpperCase, mountPrefix(f) + path, hname, h.lineNumber.getOrElse(-1))
        }
      }
    }

  case "csharp" =>
    cpg.method.where(_.annotation.name("(?i).*Http(Get|Post|Put|Delete|Patch).*")).l.flatMap { m =>
      m.file.name.headOption.map { f =>
        val base = m.typeDecl.annotation.name("Route").code.headOption.map(routeFromAttr).getOrElse("")
        val sub = m.annotation.name("(?i).*Http.*").code.headOption.map(routeFromAttr).getOrElse("")
        val verb = m.annotation.name("(?i).*Http(Get|Post|Put|Delete|Patch).*").name.headOption
          .getOrElse("Http").replace("Http", "").toUpperCase
        (f, verb, s"/$base/$sub", m.name, m.lineNumber.getOrElse(-1))
      }
    }

  case _ => // java
    cpg.method.where(_.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping")).l.flatMap { m =>
      m.file.name.headOption.map { f =>
        val base = m.typeDecl.annotation.name("RequestMapping").code.headOption.map(routeFromAttr).getOrElse("")
        val subAnn = m.annotation.name(".*(Get|Post|Put|Delete|Patch)Mapping").headOption
        val sub = subAnn.map(a => routeFromAttr(a.code)).getOrElse("")
        val verb = subAnn.map(_.name.replace("Mapping", "").toUpperCase).getOrElse("?")
        (f, verb, s"$base$sub", m.name, m.lineNumber.getOrElse(-1))
      }
    }
}

// ---- references: file-level call edges ----
val edges = scala.collection.mutable.LinkedHashSet.empty[(String, String)]
cpg.call.l.foreach { c =>
  c.file.name.headOption.filter(fileSet.contains).foreach { from =>
    c.callee.filterNot(_.isExternal).file.name.l.filter(fileSet.contains).foreach { to =>
      if (to != from) edges += ((from, to))
    }
  }
}
// unresolved-receiver fallback via the import table (python + js/ts, D5 ghost calls)
if (lang == "python" || lang == "js") {
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
  val importMap: Map[String, Map[String, String]] = allFiles.flatMap { f =>
    cpg.file.nameExact(f).ast.isImport.l.flatMap { i =>
      for (as <- i.importedAs; ent <- i.importedEntity) yield (f, as -> ent)
    }
  }.groupBy(_._1).map { case (f, rows) => f -> rows.map(_._2).toMap }
  def resolveToFile(from: String, entity: String): Option[String] =
    if (lang == "python") {
      val p = entity.replace('.', '/') + ".py"
      if (fileSet.contains(p)) Some(p) else None
    } else {
      val mod = resolveModule(from, entity)
      allFiles.find(file =>
        file == mod + ".js" || file == mod + ".ts" ||
        file == mod + "/index.js" || file == mod + "/index.ts")
    }
  val recvRe = "^([A-Za-z_$][A-Za-z0-9_$]*)\\.[A-Za-z_$]".r
  cpg.call.l.foreach { c =>
    for {
      from <- c.file.name.headOption.filter(fileSet.contains)
      m <- recvRe.findFirstMatchIn(c.code.trim)
      ent <- importMap.getOrElse(from, Map.empty).get(m.group(1))
      to <- resolveToFile(from, ent) if to != from
    } edges += ((from, to))
  }
}

// ---- assemble ----
val routesByFile = routes.groupBy(_._1)
val filesJson = allFiles.map { f =>
  obj(
    "path" -> f,
    "role" -> roleOf(f),
    "language" -> languageOf(f),
    "imports" -> cpg.file.nameExact(f).ast.isImport.importedEntity.l.flatten.distinct.sorted,
    "symbols" -> symbolsOf(f),
    "routes" -> routesByFile.getOrElse(f, Nil).sortBy(_._5).map { case (_, verb, path, fn, line) =>
      obj("method" -> verb, "path" -> path, "function" -> fn, "line" -> line)
    }
  )
}
val refsJson = edges.toList.sorted.map { case (a, b) => obj("from" -> a, "to" -> b) }

println(writeJson(obj("root" -> srcRoot, "tool" -> "joern",
  "files" -> filesJson, "references" -> refsJson), 0))
System.err.println(s"// repo_map: ${allFiles.size} files, ${routes.size} routes, ${edges.size} references (lang=$lang)")
