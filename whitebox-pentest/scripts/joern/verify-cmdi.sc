// Command injection verification script.
// Verifies whether attacker-controlled input reaches a shell-executing sink.

import $file.common, common._

@main def verify(cpgFile: String, file: String, line: Int): Unit = {
  importCpg(cpgFile)

  println(s"[*] Verifying command injection at $file:$line")

  val language = detectLanguage(file)
  val supported = supportedLanguages("command-injection")
  if (!supported.contains(language)) {
    printResult(unsupportedResult(file, "command-injection", supported))
    return
  }

  val targetSinks = callsMatching(Sinks.cmdSinksFor(language))
    .filter(c => c.file.name.headOption.getOrElse("").contains(file))
    .filter(c => c.lineNumber.getOrElse(0) == line)
    .l

  if (targetSinks.isEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", 0.0, s"No command sink found at $file:$line"))
    return
  }

  val sink = targetSinks.head
  val sources = cpg.parameter.name(Sources.parameterPattern(language, "http"))
  val anyFlows = findAttackerFlows(sink, language, "http")

  if (anyFlows.isEmpty) {
    printResult(VerificationResult("FALSE_POSITIVE", Confidence.FP_NO_DATAFLOW, "No data flow from attacker-controlled input to the command sink"))
    return
  }

  val arguments = sink.argument.l
  val isNonShellProcess =
    (sink.name == "spawn" || sink.name == "ProcessBuilder") &&
    arguments.size > 1 &&
    (sink.code.contains("[") || sink.code.contains("new ProcessBuilder"))

  if (isNonShellProcess) {
    printResult(VerificationResult("FALSE_POSITIVE", Confidence.FP_PARAMETERIZED_QUERY, "Process is launched with discrete arguments instead of a shell command string"))
    return
  }

  val typeCoerced = sink.argument.reachableBy(sources)
    .where(_.inAst.isCall.name("^(parseInt|parseFloat|Number|toInt|atoi)$"))
    .l

  if (typeCoerced.size == anyFlows.size && typeCoerced.nonEmpty) {
    printResult(VerificationResult("FALSE_POSITIVE", Confidence.FP_TYPE_COERCION, "Input is type-coerced before the command sink"))
    return
  }

  val allowlistChecks = sink.argument.reachableBy(sources)
    .where(_.inAst.isCall.name("^(allowlist|whitelist|matches|match)$"))
    .l

  if (allowlistChecks.nonEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", Confidence.NR_PARTIAL_SANITIZER, "Allowlist-style validation detected; verify the allowed command set is strict"))
    return
  }

  val shellEscaping = sink.argument.reachableBy(sources)
    .where(_.inAst.isCall.name("^(escape|quote|shellescape)$"))
    .l

  if (shellEscaping.nonEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", Confidence.NR_PARTIAL_SANITIZER, "Shell escaping detected; verify that the sink does not invoke a shell"))
    return
  }

  val flowPath = sink.argument.reachableByFlows(sources).l.headOption.map { flow =>
    val elements = flow.elements.l
    DataFlowPath(
      sourceFile = elements.headOption.flatMap(_.file.name.headOption).getOrElse("unknown"),
      sourceLine = elements.headOption.flatMap(_.lineNumber).getOrElse(0),
      sourceCode = elements.headOption.map(_.code).getOrElse(""),
      sinkFile = file,
      sinkLine = line,
      sinkCode = sink.code,
      path = elements.map(e => s"line ${e.lineNumber.getOrElse(0)}: ${e.code.take(50)}").l
    )
  }

  printResult(VerificationResult("VERIFIED", Confidence.VERIFIED_TAINT_NO_SANITIZER, "User input flows directly to a shell command sink", dataFlow = flowPath))
}
