// Path traversal verification script.
// Requires either basename-only extraction or normalization plus a prefix check
// to dismiss a finding as a false positive.

import $file.common, common._

@main def verify(cpgFile: String, file: String, line: Int): Unit = {
  importCpg(cpgFile)

  println(s"[*] Verifying path traversal at $file:$line")

  val language = detectLanguage(file)
  val supported = supportedLanguages("path-traversal")
  if (!supported.contains(language)) {
    printResult(unsupportedResult(file, "path-traversal", supported))
    return
  }

  val targetSinks = callsMatching(Sinks.pathSinksFor(language))
    .filter(c => c.file.name.headOption.getOrElse("").contains(file))
    .filter(c => c.lineNumber.getOrElse(0) == line)
    .l

  if (targetSinks.isEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", 0.0, s"No file operation sink found at $file:$line"))
    return
  }

  val sink = targetSinks.head
  val sources = cpg.parameter.name(Sources.parameterPattern(language, "path"))
  val anyFlows = findAttackerFlows(sink, language, "path")

  if (anyFlows.isEmpty) {
    printResult(VerificationResult("FALSE_POSITIVE", Confidence.FP_NO_DATAFLOW, "No data flow from attacker-controlled input to the file sink"))
    return
  }

  val hasBasename = sink.argument.reachableBy(sources)
    .where(_.inAst.isCall.name("basename"))
    .l

  if (hasBasename.size == anyFlows.size && hasBasename.nonEmpty) {
    printResult(VerificationResult("FALSE_POSITIVE", Confidence.FP_PARAMETERIZED_QUERY, "basename() strips directory components before the file sink"))
    return
  }

  // Distinguish strong normalizers (realpath, filepath.Clean) from weak ones (resolve).
  // path.resolve(base, absoluteInput) returns absoluteInput directly -- it does NOT
  // neutralize absolute-path injection the way realpath/Clean do.
  val strongNormFlows = sink.argument.reachableBy(sources)
    .where(_.inAst.isCall.name(Sanitizers.strongPathNormalization))
    .l

  val resolveOnlyFlows = sink.argument.reachableBy(sources)
    .where(_.inAst.isCall.name(Sanitizers.weakPathNormalization))
    .l

  val prefixChecks = sink.argument.reachableBy(sources)
    .where(_.inAst.isCall.name(Sanitizers.pathPrefixValidation))
    .l

  if (strongNormFlows.nonEmpty && prefixChecks.nonEmpty) {
    printResult(
      VerificationResult(
        "FALSE_POSITIVE",
        Confidence.FP_TYPE_COERCION,
        "Path is normalized (realpath/Clean) and prefix-validated after normalization",
        sanitizers = List("normalize", "prefix-check")
      )
    )
    return
  }

  if (resolveOnlyFlows.nonEmpty && prefixChecks.nonEmpty) {
    printResult(
      VerificationResult(
        "NEEDS_REVIEW",
        Confidence.NR_PARTIAL_SANITIZER,
        "path.resolve() plus prefix check detected, but resolve does not neutralize " +
        "absolute-path injection (e.g., userInput = '/etc/passwd'). Verify that the " +
        "prefix check runs AFTER resolve on the resolved value, not on the raw input.",
        sanitizers = List("resolve", "prefix-check")
      )
    )
    return
  }

  if (strongNormFlows.nonEmpty || resolveOnlyFlows.nonEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", Confidence.NR_PARTIAL_SANITIZER, "Path normalization detected without a post-normalization prefix check"))
    return
  }

  val traversalFilters = sink.argument.reachableBy(sources)
    .where(_.inAst.isCall.name("^(replace|replaceAll)$"))
    .l

  if (traversalFilters.nonEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", Confidence.NR_CONTEXT_UNCLEAR, "Blacklist-style path filtering detected; verify it cannot be bypassed"))
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

  printResult(VerificationResult("VERIFIED", Confidence.VERIFIED_TAINT_NO_SANITIZER, "User input reaches the file sink without normalization or a prefix guard", dataFlow = flowPath))
}
