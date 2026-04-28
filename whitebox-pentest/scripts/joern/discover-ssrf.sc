// SSRF discovery script.
// Scans the entire CPG for HTTP/URL request sinks reachable from user input
// without URL validation. Discovers new vulnerabilities that
// pattern-based tools like Semgrep cannot find.

import $file.common, common._

@main def discover(cpgFile: String): Unit = {
  safeImportCpg(cpgFile)

  val files = cpg.file.name.l
  if (files.isEmpty) { println("[]"); return }
  val language = files.map(detectLanguage).find(_ != Languages.unsupported).getOrElse(Languages.unsupported)
  if (language == Languages.unsupported) { println("[]"); return }

  val sinks = callsMatching(Sinks.ssrfSinksFor(language)).filterNot(c => shouldExclude(c.file.name.headOption.getOrElse(""))).l
  val results = new scala.collection.mutable.ArrayBuffer[String]()

  for (sink <- sinks) {
    val flows = findAttackerFlows(sink, language, "url")
    if (flows.nonEmpty) {
      // Check for URL validation/sanitization
      val sources = cpg.parameter.name(Sources.parameterPattern(language, "url"))
      val sanitized = try {
        sink.argument.reachableBy(sources)
          .where(_.inAst.isCall.name(Sanitizers.urlValidation)).l
      } catch { case _: Exception => List.empty }

      if (sanitized.size < flows.size) {
        val file = sink.file.name.headOption.getOrElse("unknown")
        val line = sink.lineNumber.getOrElse(0)
        val code = escapeJson(sink.code.take(100))
        results += s"""{"type":"ssrf","file":"$file","line":$line,"sink":"$code","source_tool":"joern"}"""
      }
    }
  }

  println("[" + results.mkString(",\n") + "]")
}
