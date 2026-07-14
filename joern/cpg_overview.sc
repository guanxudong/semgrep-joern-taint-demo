import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

@main def main() = {
  println("=== Loading CPG ===")
  val cpg = importCpg("bad_demo_cpg.bin").get

  println(s"\n=== Graph stats ===")
  println(s"Nodes: ${cpg.graph.nodeCount}")
  println(s"Edges: ${cpg.graph.edgeCount}")
  println(s"Methods: ${cpg.method.size}")
  println(s"Calls: ${cpg.call.size}")

  println(s"\n=== Source files ===")
  cpg.file.name.l.sorted.foreach(println)

  println(s"\n=== Method names ===")
  cpg.method.name.l.sorted.distinct.foreach(println)

  println(s"\n=== Dangerous call sites ===")
  val dangerous = cpg.call.name("""system|eval|exec|execute|pickle\.loads|yaml\.load|requests\.get|requests\.post""").l
  dangerous.foreach { c =>
    println(s"${c.method.name}: ${c.code}")
  }

  println(s"\n=== SQL execute calls ===")
  cpg.call.name("execute").code.l.foreach(println)

  println(s"\n=== Hardcoded secrets/keywords ===")
  cpg.literal.code(".*password.*|.*secret.*|.*key.*").code.l.foreach(println)
}
