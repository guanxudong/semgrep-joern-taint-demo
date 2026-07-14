import io.shiftleft.semanticcpg.language._
import os._

/**
 * Language-agnostic Semgrep -> enclosing-function mapper.
 *
 * Given a Semgrep JSON result file and a Joern CPG, print each finding's
 * enclosing function.  The only assumptions are:
 *   - The CPG contains Method nodes.
 *   - Method nodes have filename, lineNumber and lineNumberEnd.
 *   - The innermost method whose range contains the sink line is the
 *     enclosing function.
 */

@main def main() = {
  // --------------------------------------------------------------------------
  // Configuration: change these defaults or pass via your wrapper script.
  // --------------------------------------------------------------------------
  val cpgPath: String = "bad_demo_cpg.bin"
  val jsonPath: String = "semgrep_results.json"

  val cpg = importCpg(cpgPath).get
  val data = ujson.read(os.read(os.pwd / jsonPath))
  val results = data("results").arr

  def basename(p: String): String = p.split("[/\\\\]").last

  /** Try to match a Semgrep path against the filename stored in the CPG.
   *  Different Joern frontends store different filename styles (basename,
   *  relative path, absolute path), so we try several heuristics.
   */
  def matchesFilename(cpgFile: String, semgrepPath: String): Boolean = {
    val semgrepBasename = basename(semgrepPath)
    cpgFile == semgrepBasename ||
    cpgFile.endsWith(semgrepPath) ||
    semgrepPath.endsWith(cpgFile)
  }

  /** Return the innermost Method node whose line range contains `line`. */
  def enclosingMethod(path: String, line: Int): Option[io.shiftleft.codepropertygraph.generated.nodes.Method] = {
    val candidates = cpg.method
      .filter(m => matchesFilename(m.filename, path))
      .filter(m => m.lineNumber.exists(_ <= line) && m.lineNumberEnd.exists(_ >= line))
      .l

    // Innermost = largest start line (deepest nesting).
    candidates.sortBy(-_.lineNumber.getOrElse(0)).headOption
  }

  println(f"${"FILE:LINE"}%-35s ${"FUNCTION_ID"}%-55s ${"RULE"}")
  println("-" * 110)

  for (result <- results) {
    val path = result("path").str
    val line = result("start")("line").num.toInt
    val rule = result("check_id").str.split("\\.").last

    val (name, defLine) = enclosingMethod(path, line) match {
      case Some(m) =>
        // Use the simple method name.  For Java/C# etc. where class/namespace
        // context matters, replace m.name with m.fullName.
        (m.name, m.lineNumber.getOrElse(line))
      case None    =>
        ("<module>", line)
    }

    val loc = s"$path:$line"
    val funcId = s"$path:$defLine:$name"
    println(f"$loc%-35s $funcId%-55s $rule")
  }
}
