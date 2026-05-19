// Solidity access control verification script.
// Verifies whether sensitive functions in smart contracts have proper access
// control modifiers or require statements.
//
// Vulnerability Pattern: Sensitive function without access control
//   function withdraw(uint amount) public {
//       payable(msg.sender).transfer(amount);
//   }
//
// Safe Pattern: Access control modifier or require check
//   function withdraw(uint amount) public onlyOwner {
//       payable(msg.sender).transfer(amount);
//   }
//
// tx.origin Pattern: Always VERIFIED - vulnerable to phishing attacks
//   require(tx.origin == owner) // DANGEROUS - use msg.sender instead
//
// Legacy note: VulnScout does not route Solidity findings through Joern.
// Slither owns Solidity verification; this script returns NA_CPG via common.sc.

import $file.common, common._

@main def verify(cpgFile: String, file: String, line: Int): Unit = {
  importCpg(cpgFile)

  println(s"[*] Verifying access control vulnerability at $file:$line")

  val language = detectLanguage(file)
  val supported = supportedLanguages("access-control")
  if (!supported.contains(language)) {
    printResult(unsupportedResult(file, "access-control", supported))
    return
  }

  // ============================================================================
  // STEP 1: Find the sensitive function at the specified location
  // ============================================================================

  val sensitiveFunctionPatterns = "^(selfdestruct|suicide|transferOwnership|renounceOwnership|mint|burn|pause|unpause|initialize|withdraw|withdrawAll|setOwner|setAdmin|upgrade|upgradeTo|upgradeToAndCall|setImplementation|delegatecall|destroy)$"

  val targetCalls = cpg.call.name(sensitiveFunctionPatterns)
    .filter(c => c.file.name.headOption.getOrElse("").contains(file))
    .filter(c => c.lineNumber.getOrElse(0) == line)
    .l

  // Also check if the flagged line is a function definition containing sensitive operations
  val containingMethods = cpg.method
    .filter(m => m.file.name.headOption.getOrElse("").contains(file))
    .filter(m => m.lineNumber.getOrElse(0) == line)
    .l

  if (targetCalls.isEmpty && containingMethods.isEmpty) {
    // Try to find any call at that line that might be sensitive
    val anyCalls = cpg.call
      .filter(c => c.file.name.headOption.getOrElse("").contains(file))
      .filter(c => c.lineNumber.getOrElse(0) == line)
      .l

    if (anyCalls.isEmpty) {
      printResult(VerificationResult("NEEDS_REVIEW", 0.0,
        s"No sensitive function or call found at $file:$line"))
      return
    }
  }

  // Determine the method to analyze (either the method definition at line, or the method containing the call)
  val methodToAnalyze = if (containingMethods.nonEmpty) {
    containingMethods.headOption
  } else if (targetCalls.nonEmpty) {
    targetCalls.head.method.l.headOption
  } else {
    cpg.call
      .filter(c => c.file.name.headOption.getOrElse("").contains(file))
      .filter(c => c.lineNumber.getOrElse(0) == line)
      .l.headOption.flatMap(_.method.l.headOption)
  }

  if (methodToAnalyze.isEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", 0.3,
      "Could not determine the containing function for access control analysis"))
    return
  }

  val method = methodToAnalyze.get
  val methodName = method.name
  val methodCode = method.code

  println(s"[*] Analyzing function: $methodName")

  // ============================================================================
  // STEP 2: Check for tx.origin usage (always vulnerable)
  // ============================================================================

  val txOriginUsage = cpg.call
    .filter(c => c.method.name.headOption.getOrElse("") == methodName)
    .filter(c => c.file.name.headOption.getOrElse("").contains(file))
    .filter(c => c.code.contains("tx.origin"))
    .l

  if (txOriginUsage.nonEmpty) {
    val txOriginLine = txOriginUsage.head.lineNumber.getOrElse(0)
    val dataFlow = DataFlowPath(
      sourceFile = file,
      sourceLine = txOriginLine,
      sourceCode = txOriginUsage.head.code.take(100),
      sinkFile = file,
      sinkLine = line,
      sinkCode = targetCalls.headOption.map(_.code.take(100)).getOrElse(methodName),
      path = List(
        s"line $txOriginLine: tx.origin used for authorization",
        s"line $line: sensitive operation ${targetCalls.headOption.map(_.name).getOrElse(methodName)}"
      )
    )

    printResult(VerificationResult("VERIFIED", 0.95,
      "tx.origin is used for access control - vulnerable to phishing attacks via malicious contract forwarding. Use msg.sender instead.",
      dataFlow = Some(dataFlow)))
    return
  }

  // ============================================================================
  // STEP 3: Check for access control modifiers
  // ============================================================================

  val accessModifiers = List(
    "onlyOwner", "onlyAdmin", "onlyRole", "onlyMinter", "onlyPauser",
    "onlyGovernance", "onlyAuthorized", "onlyOperator", "onlyManager",
    "whenNotPaused", "whenPaused", "initializer", "reinitializer",
    "nonReentrant"
  )

  val hasModifier = accessModifiers.exists { mod =>
    methodCode.contains(mod)
  }

  if (hasModifier) {
    val foundModifiers = accessModifiers.filter(mod => methodCode.contains(mod))
    printResult(VerificationResult("FALSE_POSITIVE", 0.90,
      s"Access control modifier detected: ${foundModifiers.mkString(", ")}",
      sanitizers = foundModifiers))
    return
  }

  // ============================================================================
  // STEP 4: Check for require/assert access control patterns
  // ============================================================================

  val methodCallsInFunc = cpg.call
    .filter(c => c.method.name.headOption.getOrElse("") == methodName)
    .filter(c => c.file.name.headOption.getOrElse("").contains(file))
    .l

  // Check for require(msg.sender == owner) patterns
  val requireChecks = methodCallsInFunc.filter { c =>
    c.name == "require" || c.name == "assert" || c.name == "revert"
  }

  val hasSenderCheck = requireChecks.exists { c =>
    c.code.contains("msg.sender") && (
      c.code.contains("owner") ||
      c.code.contains("admin") ||
      c.code.contains("operator") ||
      c.code.contains("governance") ||
      c.code.contains("authorized") ||
      c.code.contains("role") ||
      c.code.contains("hasRole")
    )
  }

  if (hasSenderCheck) {
    printResult(VerificationResult("FALSE_POSITIVE", 0.85,
      "require/assert statement with msg.sender authorization check detected",
      sanitizers = List("require(msg.sender)")))
    return
  }

  // Check for OpenZeppelin AccessControl hasRole pattern
  val hasRoleCheck = methodCallsInFunc.exists { c =>
    c.code.contains("hasRole") ||
    c.code.contains("_checkRole") ||
    c.code.contains("AccessControl")
  }

  if (hasRoleCheck) {
    printResult(VerificationResult("FALSE_POSITIVE", 0.90,
      "OpenZeppelin AccessControl role check detected",
      sanitizers = List("hasRole")))
    return
  }

  // Check for initializer guard (OpenZeppelin Initializable)
  if (methodName == "initialize" || methodName == "init") {
    val hasInitGuard = methodCode.contains("initializer") ||
      methodCode.contains("reinitializer") ||
      methodCallsInFunc.exists(c => c.code.contains("_disableInitializers") || c.code.contains("initialized"))

    if (hasInitGuard) {
      printResult(VerificationResult("FALSE_POSITIVE", 0.90,
        "Initializer guard detected - function can only be called once",
        sanitizers = List("initializer")))
      return
    }
  }

  // ============================================================================
  // STEP 5: Check if function visibility is internal/private (not externally callable)
  // ============================================================================

  val isInternal = methodCode.contains("internal") || methodCode.contains("private")

  if (isInternal) {
    printResult(VerificationResult("FALSE_POSITIVE", 0.85,
      "Function is internal/private - not directly callable by external accounts"))
    return
  }

  // ============================================================================
  // STEP 6: Determine what sensitive operations are unprotected
  // ============================================================================

  val sensitiveOps = methodCallsInFunc.filter { c =>
    c.name.matches(sensitiveFunctionPatterns)
  }.map(_.name).distinct

  val ethTransfers = methodCallsInFunc.filter { c =>
    c.code.contains(".transfer(") ||
    c.code.contains(".send(") ||
    c.code.contains(".call{value:")
  }

  val allSensitive = sensitiveOps ++ (if (ethTransfers.nonEmpty) List("ETH transfer") else List.empty)

  val reason = if (allSensitive.nonEmpty) {
    s"Sensitive operation(s) [${allSensitive.mkString(", ")}] in function $methodName lack access control - any address can call this function"
  } else {
    s"Function $methodName is publicly callable without access control restrictions"
  }

  printResult(VerificationResult("VERIFIED", 0.90, reason))
}
