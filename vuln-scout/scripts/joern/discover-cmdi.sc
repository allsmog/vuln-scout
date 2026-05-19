// Command injection discovery script.
// Scans the entire CPG for command execution sinks reachable from HTTP sources
// without input validation. Discovers new vulnerabilities that
// pattern-based tools like Semgrep cannot find.

import $file.common, common._

@main def discover(cpgFile: String): Unit = {
  safeImportCpg(cpgFile)

  val files = cpg.file.name.l
  if (files.isEmpty) { println("[]"); return }
  val language = files.map(detectLanguage).find(_ != Languages.unsupported).getOrElse(Languages.unsupported)
  if (language == Languages.unsupported) { println("[]"); return }

  val sinks = callsMatching(Sinks.cmdSinksFor(language)).filterNot(c => shouldExclude(c.file.name.headOption.getOrElse(""))).l
  val results = new scala.collection.mutable.ArrayBuffer[String]()

  for (sink <- sinks) {
    val flows = findAttackerFlows(sink, language, "http")
    if (flows.nonEmpty) {
      // Check for command validation/sanitization
      val sources = cpg.parameter.name(Sources.parameterPattern(language, "http"))
      val sanitized = try {
        sink.argument.reachableBy(sources)
          .where(_.inAst.isCall.name(Sanitizers.commandValidation)).l
      } catch { case _: Exception => List.empty }

      if (sanitized.size < flows.size) {
        val file = sink.file.name.headOption.getOrElse("unknown")
        val line = sink.lineNumber.getOrElse(0)
        val code = escapeJson(sink.code.take(100))
        results += s"""{"type":"command-injection","file":"$file","line":$line,"sink":"$code","source_tool":"joern"}"""
      }
    }
  }

  println("[" + results.mkString(",\n") + "]")
}
