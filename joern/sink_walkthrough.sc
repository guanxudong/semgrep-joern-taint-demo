import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import scala.io.Source
import scala.util.{Try, Success, Failure}

def readLines(path: String): List[String] =
  Try(Source.fromFile(path).getLines().toList) match {
    case Success(lines) => lines
    case Failure(_)     => Nil
  }

def snippet(path: String, start: Int, end: Int): String = {
  val lines = readLines(path)
  val s = math.max(1, start)
  val e = math.min(lines.size, end)
  (s to e).map(i => f"$i%4d | ${lines(i - 1)}").mkString("\n")
}

def loc(node: io.shiftleft.codepropertygraph.generated.nodes.AstNode): String = {
  val file = node.file.name.headOption.getOrElse("?")
  val line = node.lineNumber.getOrElse(-1)
  s"$file:$line"
}

@main def main() = {
  val cpg = importCpg("bad_demo_cpg.bin").get

  println("=== Joern sink-to-source walkthrough ===")
  println("Sink method: db.py:search_users_unsafe -> cursor.execute(query)\n")

  // 1) Select the sink call
  val sinkCall = cpg.call.name("execute").where(_.method.name("search_users_unsafe")).head
  println(s"[1] SINK call: ${sinkCall.code}")
  println(s"    Location : ${loc(sinkCall)}")
  println(s"    In method: ${sinkCall.method.name}\n")

  // 2) Backward taint inside the sink method (parameter -> sink argument)
  val sinkArg = sinkCall.argument(1)
  val params  = cpg.method.name("search_users_unsafe").parameter.name("term")
  val reached = sinkArg.reachableBy(params)
  println(s"[2] Intra-method taint (parameter -> sink argument)")
  println(s"    sink argument   : ${sinkArg.code}")
  println(s"    source parameter: term")
  println(s"    reachable       : ${reached.nonEmpty}\n")

  // 3) Upward call graph: who calls the sink method?
  val sinkMethod = sinkCall.method
  val callers    = sinkMethod.caller.name.l.distinct
  println(s"[3] Call graph (upward from ${sinkMethod.name})")
  println(s"    direct callers: ${callers.mkString(", ")}")

  // Show the actual call sites
  cpg.call.name(sinkMethod.name).foreach { callSite =>
    println(s"    ${loc(callSite)}  ${callSite.method.name}: ${callSite.code}")
  }
  println()

  // 4) Find the source in the caller (request.args.get)
  val sourceCall = cpg.call.name("get").where(_.method.name("search")).headOption
  sourceCall match {
    case Some(src) =>
      println(s"[4] Source in caller method 'search'")
      println(s"    ${loc(src)}  ${src.code}\n")

      // 5) Combined code snippet
      val srcMethod  = src.method
      val srcPath    = "src/bad_demo/" + src.file.name.headOption.getOrElse("")
      val sinkPath   = "src/bad_demo/" + sinkCall.file.name.headOption.getOrElse("")
      val srcStart   = srcMethod.lineNumber.getOrElse(src.lineNumber.getOrElse(1))
      val srcEnd     = srcMethod.lineNumberEnd.getOrElse(src.lineNumber.getOrElse(1))
      val sinkStart  = sinkMethod.lineNumber.getOrElse(sinkCall.lineNumber.getOrElse(1))
      val sinkEnd    = sinkMethod.lineNumberEnd.getOrElse(sinkCall.lineNumber.getOrElse(1))

      println("[5] Combined sink-to-source snippet\n")
      println(s"--- SOURCE method: ${srcMethod.name} ($srcPath:$srcStart-$srcEnd) ---")
      println(snippet(srcPath, srcStart, srcEnd))
      println()
      println(s"--- SINK method: ${sinkMethod.name} ($sinkPath:$sinkStart-$sinkEnd) ---")
      println(snippet(sinkPath, sinkStart, sinkEnd))

    case None =>
      println("[4] Could not locate source call request.args.get in 'search'")
  }

  println("\n=== Done ===")
}
