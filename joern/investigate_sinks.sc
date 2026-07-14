import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

@main def main() = {
  val cpg = importCpg("bad_demo_cpg.bin").get

  println("=== Investigate each SQL execute sink ===\n")

  cpg.call.name("execute").foreach { sink =>
    val method = sink.method
    println(s"SINK: ${sink.code}")
    println(s"  -> inside method: ${method.name}")
    println(s"  -> parameters: ${method.parameter.name.l.mkString(", ")}")

    // Try each parameter to see if it reaches the sink argument
    val reachableParams = method.parameter.filter { p =>
      sink.argument.reachableBy(p).nonEmpty
    }
    if (reachableParams.isEmpty) {
      println(s"  -> NO parameter reaches this execute argument")
    } else {
      println(s"  -> reachable parameters: ${reachableParams.name.l.mkString(", ")}")
    }

    // Find callers of this method
    val callers = method.caller.name.l.distinct
    println(s"  -> called by: ${callers.mkString(", ")}")

    // Show the call sites
    cpg.call.name(method.name).foreach { call =>
      println(s"     ${call.method.name}: ${call.code}")
    }
    println()
  }
}
