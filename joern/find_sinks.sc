import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

@main def main() = {
  val cpg = importCpg("bad_demo_cpg.bin").get

  println("=== SQL Injection Sinks ===")
  cpg.call.name("execute|executemany|executescript").foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== OS Command Injection Sinks ===")
  cpg.call.name("system|popen|exec|eval").foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== Deserialization Sinks ===")
  cpg.call.name("loads|load|unsafe_load").foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== SSRF / Outgoing Request Sinks ===")
  cpg.call.name("get|post|put|delete|request").where(_.code(".*requests\\..*|.*urllib.*")).foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== XSS / Template Sinks ===")
  cpg.call.name("render_template_string|Markup|render_search_results|render_comment").foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== LDAP Sinks ===")
  cpg.call.name("search|bind").foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== Crypto / Hash Sinks ===")
  cpg.call.name("md5|sha1|new").where(_.code(".*md5.*|.*sha1.*|.*hmac.*|.* Fernet .*")).foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== Logging Sensitive Data Sinks ===")
  cpg.call.name("info|error|warning|debug").foreach { c =>
    println(s"  ${c.method.name}: ${c.code}")
  }

  println("\n=== Hardcoded Secrets / Literals ===")
  cpg.literal.code(".*secret.*|.*password.*|.*key.*|.*token.*").foreach { l =>
    println(s"  ${l.method.name}: ${l.code}")
  }
}
