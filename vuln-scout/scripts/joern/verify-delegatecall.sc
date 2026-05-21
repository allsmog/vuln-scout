// Solidity delegatecall verification script.
// Verifies whether delegatecall usage is safe or if the target address
// can be controlled by an attacker.
//
// Vulnerability Pattern: User-controlled delegatecall target
//   function execute(address target, bytes calldata data) public {
//       target.delegatecall(data);  // attacker controls target
//   }
//
// Safe Patterns:
//   - OpenZeppelin proxy pattern with EIP-1967 storage slot
//   - Hardcoded implementation address
//   - Access-controlled upgrade functions
//
// Legacy note: VulnScout does not route Solidity findings through Joern.
// Slither owns Solidity verification; this script returns NA_CPG via common.sc.

import $file.common, common._

@main def verify(cpgFile: String, file: String, line: Int): Unit = {
  importCpg(cpgFile)

  println(s"[*] Verifying delegatecall vulnerability at $file:$line")

  val language = detectLanguage(file)
  val supported = supportedLanguages("delegatecall")
  if (!supported.contains(language)) {
    printResult(unsupportedResult(file, "delegatecall", supported))
    return
  }

  // ============================================================================
  // STEP 1: Find delegatecall usage at the specified location
  // ============================================================================

  val targetCalls = cpg.call
    .filter(c => c.file.name.headOption.getOrElse("").contains(file))
    .filter(c => c.lineNumber.getOrElse(0) == line)
    .filter(c => c.code.contains("delegatecall"))
    .l

  if (targetCalls.isEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", 0.0, s"No delegatecall found at $file:$line"))
    return
  }

  val delegateCall = targetCalls.head
  val delegateCode = delegateCall.code

  println(s"[*] Found delegatecall: ${delegateCode.take(80)}")

  // ============================================================================
  // STEP 2: Determine the containing function
  // ============================================================================

  val containingMethod = delegateCall.method.l.headOption

  if (containingMethod.isEmpty) {
    printResult(VerificationResult("NEEDS_REVIEW", 0.4,
      "Could not determine containing function for delegatecall analysis"))
    return
  }

  val method = containingMethod.get
  val methodName = method.name
  val methodCode = method.code

  println(s"[*] Containing function: $methodName")

  // ============================================================================
  // STEP 3: Check for OpenZeppelin proxy patterns (safe)
  // ============================================================================

  val fileCalls = cpg.call
    .filter(c => c.file.name.headOption.getOrElse("").contains(file))
    .l

  // Check for EIP-1967 implementation slot
  val eip1967Slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
  val hasEIP1967 = fileCalls.exists(c => c.code.contains(eip1967Slot)) ||
    fileCalls.exists(c =>
      c.code.contains("_IMPLEMENTATION_SLOT") ||
      c.code.contains("IMPLEMENTATION_SLOT") ||
      c.code.contains("eip1967.proxy.implementation"))

  if (hasEIP1967) {
    // Check if upgrade function has access control
    val upgradeMethod = cpg.method
      .filter(m => m.file.name.headOption.getOrElse("").contains(file))
      .filter(m =>
        m.name.contains("upgrade") ||
        m.name.contains("setImplementation") ||
        m.name == "_setImplementation")
      .l

    val upgradeHasAccess = upgradeMethod.exists { m =>
      m.code.contains("onlyOwner") ||
      m.code.contains("onlyAdmin") ||
      m.code.contains("_checkOwner") ||
      m.code.contains("onlyProxy") ||
      m.code.contains("ifAdmin")
    }

    if (upgradeHasAccess) {
      printResult(VerificationResult("FALSE_POSITIVE", 0.95,
        "EIP-1967 proxy pattern with access-controlled upgrade function detected",
        sanitizers = List("EIP-1967", "access-controlled upgrade")))
      return
    }

    printResult(VerificationResult("NEEDS_REVIEW", 0.60,
      "EIP-1967 proxy pattern detected but upgrade access control could not be confirmed"))
    return
  }

  // Check for OpenZeppelin Proxy/TransparentUpgradeableProxy/UUPSUpgradeable patterns
  val ozProxyPatterns = fileCalls.exists { c =>
    c.code.contains("TransparentUpgradeableProxy") ||
    c.code.contains("UUPSUpgradeable") ||
    c.code.contains("ERC1967Proxy") ||
    c.code.contains("BeaconProxy") ||
    c.code.contains("_fallback") ||
    c.code.contains("_delegate")
  }

  if (ozProxyPatterns) {
    printResult(VerificationResult("FALSE_POSITIVE", 0.90,
      "OpenZeppelin proxy pattern detected - delegatecall is part of a standard proxy mechanism",
      sanitizers = List("OpenZeppelin Proxy")))
    return
  }

  // ============================================================================
  // STEP 4: Check if the delegatecall target is user-controlled
  // ============================================================================

  val sources = cpg.parameter.name(Sources.parameterPattern(language, "http"))
  val parameterFlows = delegateCall.argument.reachableBy(sources).l

  // Check if the target address comes from a function parameter
  val methodParams = method.parameter.l
  val targetFromParam = methodParams.exists { p =>
    delegateCode.contains(p.name) && (
      p.typeFullName.contains("address") ||
      p.name.contains("target") ||
      p.name.contains("impl") ||
      p.name.contains("implementation") ||
      p.name.contains("to") ||
      p.name.contains("dest") ||
      p.name.contains("addr")
    )
  }

  if (targetFromParam) {
    // Target address is from a parameter - check if there's access control on the function
    val hasAccessControl = methodCode.contains("onlyOwner") ||
      methodCode.contains("onlyAdmin") ||
      methodCode.contains("onlyProxy") ||
      methodCode.contains("require(msg.sender")

    if (hasAccessControl) {
      printResult(VerificationResult("NEEDS_REVIEW", 0.60,
        "delegatecall target comes from a parameter but function has access control - verify the access control is sufficient",
        sanitizers = List("access-control")))
      return
    }

    val dataFlow = DataFlowPath(
      sourceFile = file,
      sourceLine = method.lineNumber.getOrElse(0),
      sourceCode = s"function $methodName parameter",
      sinkFile = file,
      sinkLine = line,
      sinkCode = delegateCode.take(100),
      path = List(
        s"line ${method.lineNumber.getOrElse(0)}: function $methodName receives target address as parameter",
        s"line $line: delegatecall to user-controlled address"
      )
    )

    printResult(VerificationResult("VERIFIED", 0.95,
      "delegatecall target address is user-controlled via function parameter without access control - attacker can execute arbitrary code in contract context",
      dataFlow = Some(dataFlow)))
    return
  }

  // ============================================================================
  // STEP 5: Check if target is hardcoded or from trusted storage
  // ============================================================================

  // Check if the target is a state variable (storage slot) - may be safe if set by constructor/admin
  val stateVarPattern = cpg.member
    .filter(m => m.file.name.headOption.getOrElse("").contains(file))
    .filter(m => delegateCode.contains(m.name))
    .l

  if (stateVarPattern.nonEmpty) {
    // Target comes from a state variable - check who can set it
    val setterCalls = cpg.call
      .filter(c => c.file.name.headOption.getOrElse("").contains(file))
      .filter(c => stateVarPattern.exists(sv => c.code.contains(sv.name + " =")))
      .l

    val setterMethods = setterCalls.flatMap(_.method.l).distinct

    val allSettersProtected = setterMethods.forall { m =>
      m.code.contains("onlyOwner") ||
      m.code.contains("onlyAdmin") ||
      m.code.contains("require(msg.sender") ||
      m.name == "<init>" ||
      m.name == "constructor"
    }

    if (allSettersProtected) {
      printResult(VerificationResult("FALSE_POSITIVE", 0.80,
        "delegatecall target is from a state variable that can only be set by privileged accounts",
        sanitizers = List("admin-controlled state variable")))
      return
    }

    printResult(VerificationResult("NEEDS_REVIEW", 0.60,
      "delegatecall target comes from a state variable - verify who can modify it"))
    return
  }

  // ============================================================================
  // STEP 6: Check for access control on the delegatecall function
  // ============================================================================

  val hasAccess = methodCode.contains("onlyOwner") ||
    methodCode.contains("onlyAdmin") ||
    methodCode.contains("require(msg.sender") ||
    methodCode.contains("internal") ||
    methodCode.contains("private")

  if (hasAccess) {
    printResult(VerificationResult("NEEDS_REVIEW", 0.50,
      "delegatecall function has access control - verify the implementation contract is trusted"))
    return
  }

  // No clear mitigation found
  printResult(VerificationResult("VERIFIED", 0.85,
    "delegatecall in a publicly accessible function without clear access control or proxy pattern - potential for arbitrary code execution in contract context"))
}
