import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

@main def main() = {
  val cpg = importCpg("bad_demo_cpg.bin").get

  println("=== Step 1: Find all SQL execute sinks ===")
  val sqlSinks = cpg.call.name("execute")
  sqlSinks.foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== Step 2: Intra-method taint (parameter -> sink) ===")
  val executeArg = sqlSinks.argument
  val params = cpg.method.name("search_users_unsafe").parameter
  val reachable = executeArg.reachableBy(params)
  println(s"Found ${reachable.size} parameter-to-sink reach(es)")
  reachable.p.foreach(println)

  println("\n=== Step 3: Find callers of the sink method ===")
  cpg.method.name("search_users_unsafe").caller.name.l.distinct.foreach(println)

  println("\n=== Step 4: See how callers pass arguments ===")
  cpg.call.name("search_users_unsafe").foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== Same for OS command injection ===")
  cpg.call.name("system").foreach { c => println(s"  ${c.method.name}: ${c.code}") }
  val sysReach = cpg.call.name("system").argument.reachableBy(
    cpg.method.name("run_ping").parameter
  )
  println(s"hostname -> system reach: ${sysReach.size}")
  cpg.method.name("run_ping").caller.name.l.distinct.foreach(println)
  cpg.call.name("run_ping").foreach { c => println(s"  ${c.method.name}: ${c.code}") }
}
