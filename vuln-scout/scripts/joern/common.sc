// Common utilities for Joern verification scripts.
// Used by all verify-*.sc scripts.
// Note: When running via `joern --script`, Joern provides its own EngineContext
// in scope, so we do not redefine it here to avoid ambiguity.

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

// Safe wrapper for importCpg that catches post-processing pass errors.
// Joern's TypeScript frontend can crash on certain patterns (e.g.
// "Assignment statement with 3 arguments" in ObjectPropertyCallLinker).
// The base CPG is still usable after catching the exception.
def safeImportCpg(path: String): Unit = {
  try {
    importCpg(path)
  } catch {
    case e: Exception =>
      System.err.println(s"[WARN] CPG post-processing error (continuing): ${e.getMessage.take(80)}")
  }
}

// Heuristic fallback: check if a sink's arguments contain user-input patterns
// in the source code text. Used when Joern's formal data flow analysis can't
// track through template literals or complex expressions.
def sinkArgContainsUserInput(sink: io.shiftleft.codepropertygraph.generated.nodes.Call, language: String): Boolean = {
  val argCode = sink.argument.code.l.mkString(" ")
  val pattern = Sources.fieldPattern(language, "http")
  pattern.split("\\|").exists(p =>
    try { argCode.matches(s"(?si).*$p.*") } catch { case _: Exception => false }
  )
}

object Languages {
  val javascript = "javascript"
  val typescript = "typescript"
  val python = "python"
  val go = "go"
  val java = "java"
  val solidity = "solidity"
  val php = "php"
  val ruby = "ruby"
  val csharp = "csharp"
  val unsupported = "unsupported"

  def detectLanguage(file: String): String = {
    val lower = file.toLowerCase
    if (lower.endsWith(".tsx") || lower.endsWith(".ts")) typescript
    else if (lower.endsWith(".jsx") || lower.endsWith(".js")) javascript
    else if (lower.endsWith(".py")) python
    else if (lower.endsWith(".go")) go
    else if (lower.endsWith(".java")) java
    else if (lower.endsWith(".sol")) solidity
    else if (lower.endsWith(".php")) php
    else if (lower.endsWith(".rb")) ruby
    else if (lower.endsWith(".cs")) csharp
    else unsupported
  }
}

def detectLanguage(file: String): String = Languages.detectLanguage(file)

def supportedLanguages(vulnType: String): Set[String] = vulnType match {
  case "reentrancy" =>
    Set.empty[String]
  case "integer-overflow" =>
    Set.empty[String]
  case "xxe" =>
    Set(Languages.java, Languages.python, Languages.php, Languages.go)
  case "ssti" =>
    Set(Languages.python, Languages.php, Languages.javascript, Languages.typescript)
  case "deserialization" =>
    Set(Languages.python, Languages.java, Languages.php)
  case "ldap-injection" =>
    Set(Languages.python, Languages.java, Languages.php)
  case "insecure-randomness" =>
    Set(Languages.javascript, Languages.typescript, Languages.python, Languages.java, Languages.go, Languages.csharp)
  case "access-control" =>
    Set.empty[String]
  case "delegatecall" =>
    Set.empty[String]
  case _ =>
    Set(
      Languages.javascript,
      Languages.typescript,
      Languages.python,
      Languages.go,
      Languages.java,
      Languages.php,
      Languages.ruby,
      Languages.csharp
    )
}

def unsupportedResult(file: String, vulnType: String, supported: Set[String]): VerificationResult = {
  VerificationResult(
    verdict = "NA_CPG",
    confidence = 0.0,
    reason =
      s"CPG verification for $vulnType is not implemented for ${detectLanguage(file)}. " +
      s"Supported languages: ${supported.toList.sorted.mkString(", ")}"
  )
}

object Sources {
  private val parameterPatterns = Map(
    Languages.javascript -> Map(
      "http" -> "req|request|params|query|body|headers|cookies|ctx",
      "path" -> "req|request|params|query|path|file|name",
      "url" -> "req|request|url|uri|target|host|endpoint"
    ),
    Languages.typescript -> Map(
      "http" -> "req|request|params|query|body|headers|cookies|ctx",
      "path" -> "req|request|params|query|path|file|name",
      "url" -> "req|request|url|uri|target|host|endpoint"
    ),
    Languages.python -> Map(
      "http" -> "request|args|form|json|values|files|body|data|payload",
      "path" -> "request|path|file|filename|name|payload",
      "url" -> "request|url|uri|target|host|endpoint"
    ),
    Languages.go -> Map(
      "http" -> "r|req|request|ctx|body|query|form|header",
      "path" -> "r|req|request|path|file|name",
      "url" -> "r|req|request|target|url|uri|host"
    ),
    Languages.java -> Map(
      "http" -> "request|req|body|input|query|param|pathVariable",
      "path" -> "request|req|path|file|name|pathVariable",
      "url" -> "request|req|target|url|uri|host|endpoint"
    ),
    Languages.php -> Map(
      "http" -> "GET|POST|REQUEST|COOKIE|SERVER|input|data|body",
      "path" -> "GET|POST|REQUEST|file|name|path",
      "url" -> "GET|POST|REQUEST|url|uri|target|host"
    ),
    Languages.ruby -> Map(
      "http" -> "params|request|body|query|headers|cookies",
      "path" -> "params|request|path|file|name",
      "url" -> "params|request|url|uri|target|host"
    ),
    Languages.csharp -> Map(
      "http" -> "request|req|context|httpContext|body|query|form|headers|cookies",
      "path" -> "request|req|path|file|filename|name",
      "url" -> "request|req|target|url|uri|host|endpoint"
    )
  )

  private val fieldPatterns = Map(
    Languages.javascript -> Map(
      "http" -> "req\\.|request\\.|ctx\\.",
      "path" -> "req\\.|request\\.|ctx\\.|path\\.|file\\.",
      "url" -> "req\\.|request\\.|ctx\\.|url\\.|host\\."
    ),
    Languages.typescript -> Map(
      "http" -> "req\\.|request\\.|ctx\\.",
      "path" -> "req\\.|request\\.|ctx\\.|path\\.|file\\.",
      "url" -> "req\\.|request\\.|ctx\\.|url\\.|host\\."
    ),
    Languages.python -> Map(
      "http" -> "request\\.(args|form|json|values|files|data|GET|POST|META|body)|flask\\.request",
      "path" -> "request\\.(args|form|json|values|files)|path|filename",
      "url" -> "request\\.(args|form|json|values)|url|host|target"
    ),
    Languages.go -> Map(
      "http" -> "(r|req)\\.(URL|Body|Form|Header)|Context\\(|FormValue|ParseForm",
      "path" -> "(r|req)\\.(URL|Body|Form)|filepath\\.",
      "url" -> "(r|req)\\.(URL|Body|Form)|http\\."
    ),
    Languages.java -> Map(
      "http" -> "request\\.|req\\.|@RequestParam|@PathVariable|@RequestBody|getParameter|getHeader|getQueryString",
      "path" -> "request\\.|req\\.|@PathVariable|PathVariable",
      "url" -> "request\\.|req\\.|@RequestParam|@RequestBody|URI|URL"
    ),
    Languages.php -> Map(
      "http" -> "\\$_(GET|POST|REQUEST|COOKIE|SERVER)|file_get_contents\\(|php://input",
      "path" -> "\\$_(GET|POST|REQUEST)|\\$_FILES",
      "url" -> "\\$_(GET|POST|REQUEST)|curl_"
    ),
    Languages.ruby -> Map(
      "http" -> "params\\[|request\\.|cookies\\[|env\\[",
      "path" -> "params\\[|request\\.|File\\.",
      "url" -> "params\\[|request\\.|URI\\."
    ),
    Languages.csharp -> Map(
      "http" -> "Request\\.|HttpContext\\.|Request\\.Query|Request\\.Form|Request\\.Headers|Request\\.Body",
      "path" -> "Request\\.|HttpContext\\.|Request\\.Query|Request\\.Form|Path\\.|File\\.",
      "url" -> "Request\\.|HttpContext\\.|Request\\.Query|Uri|Url"
    )
  )

  private val callPatterns = Map(
    Languages.python -> Map(
      "http" -> "^(get|getlist|to_dict|get_json)$",
      "path" -> "^(get|getlist|get_json)$",
      "url" -> "^(get|getlist|get_json)$"
    ),
    Languages.java -> Map(
      "http" -> "^(getParameter|getHeader|getQueryString|getRequestURI|getPathInfo|getInputStream|getReader)$",
      "path" -> "^(getParameter|getPathInfo|getRequestURI)$",
      "url" -> "^(getParameter|getRequestURL|getQueryString)$"
    ),
    Languages.go -> Map(
      "http" -> "^(FormValue|PostFormValue|ParseForm|ParseMultipartForm|ReadAll|ReadBody)$",
      "path" -> "^(FormValue|Vars)$",
      "url" -> "^(FormValue|RequestURI)$"
    ),
    Languages.php -> Map(
      "http" -> "^(input|get|post|request|cookie|header|query|all|file)$",
      "path" -> "^(input|get|request|file)$",
      "url" -> "^(input|get|request|url)$"
    ),
    Languages.ruby -> Map(
      "http" -> "^(params|permit|require|fetch)$",
      "path" -> "^(params|permit|require)$",
      "url" -> "^(params|permit|require)$"
    ),
    Languages.csharp -> Map(
      "http" -> "^(get_Query|get_Form|get_Body|get_Headers|ReadToEnd|ReadAsStringAsync)$",
      "path" -> "^(get_Query|get_Form|ReadToEnd|ReadAsStringAsync)$",
      "url" -> "^(get_Query|get_Url|get_Host|ReadAsStringAsync)$"
    )
  )

  private val globalAccessPatterns = Map(
    Languages.python -> "request",
    Languages.php -> "\\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)"
  )

  def parameterPattern(language: String, focus: String = "http"): String = {
    parameterPatterns.getOrElse(language, Map.empty).getOrElse(focus, "a^")
  }

  def fieldPattern(language: String, focus: String = "http"): String = {
    fieldPatterns.getOrElse(language, Map.empty).getOrElse(focus, "a^")
  }

  def callPattern(language: String, focus: String = "http"): String = {
    callPatterns.getOrElse(language, Map.empty).getOrElse(focus, "a^")
  }

  def globalAccessPattern(language: String): String = {
    globalAccessPatterns.getOrElse(language, "a^")
  }
}

object Sinks {
  val sqlSinks = "^(query|execute|raw|rawQuery|knex|sequelize|PreparedStatement|createStatement)$"
  val cmdSinks = "execSync|spawn|spawnSync|execFile|system|popen|ProcessBuilder|Runtime\\.exec|check_output|check_call|Popen|run"
  val xssSinks = "send|write|render|html|innerHTML|writeln|print|println"
  val pathSinks = "readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|open|stat|Files\\.read|Files\\.write|os\\.Open"
  val ssrfSinks = "fetch|request|axios|got|needle|superagent|http.get|https.get|http.request|https.request|urllib|urlopen|requests\\.get|requests\\.post|http\\.Get|RestTemplate|WebClient"
  val deserSinks = "parse|load|loads|unserialize|deserialize|readObject"
  val xxeSinks = "^(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReader|TransformerFactory|parse|parseString|fromstring|iterparse|simplexml_load_string|simplexml_load_file|DOMDocument|NewDecoder|Unmarshal)$"
  val sstiSinks = "^(render_template_string|Template|createTemplate|loadTemplate|renderString|compile|render_string)$"
  val ldapSinks = "^(ldap_search|ldap_list|ldap_read|ldap_compare|search_s|search_ext_s)$"
  val randomnessSinks = "^(random|Math\\.random|randint|randrange|choice|shuffle|Random|ThreadLocalRandom|rand\\.Intn|rand\\.Int|block\\.timestamp|blockhash|block\\.prevrandao|block\\.difficulty)$"

  // Language-specific SQL sinks
  val pythonSqlSinks = "^(execute|executemany|raw|extra|cursor|fetchone|fetchall)$"
  val javaSqlSinks = "^(executeUpdate|executeQuery|createQuery|createNativeQuery|executeNativeQuery)$"
  val goSqlSinks = "^(QueryRow|Exec|Query|QueryContext|ExecContext|QueryRowContext)$"
  val phpSqlSinks = "^(mysql_query|mysqli_query|pg_query|query)$"
  val rubySqlSinks = "^(find_by_sql|where|joins|having|select|execute)$"
  val csharpSqlSinks = "^(ExecuteReader|ExecuteScalar|ExecuteNonQuery|ExecuteSqlRaw|FromSqlRaw|SqlQuery|CreateCommand)$"

  def sqlSinksFor(language: String): String = language match {
    case Languages.python => "(" + sqlSinks + ")|" + pythonSqlSinks
    case Languages.java => "(" + sqlSinks + ")|" + javaSqlSinks
    case Languages.go => "(" + sqlSinks + ")|" + goSqlSinks
    case Languages.php => "(" + sqlSinks + ")|" + phpSqlSinks
    case Languages.ruby => "(" + sqlSinks + ")|" + rubySqlSinks
    case Languages.csharp => "(" + sqlSinks + ")|" + csharpSqlSinks
    case _ => sqlSinks
  }

  def cmdSinksFor(language: String): String = language match {
    case Languages.python => "(" + cmdSinks + ")|^(system|popen|Popen|run|call|check_call|check_output)$"
    case Languages.go => "(" + cmdSinks + ")|^(Command|CommandContext|Run|Start|CombinedOutput|Output)$"
    case Languages.java => "(" + cmdSinks + ")|^(exec|start)$"
    case Languages.php => "(" + cmdSinks + ")|^(system|exec|shell_exec|passthru|popen|proc_open)$"
    case Languages.ruby => "(" + cmdSinks + ")|^(system|exec|spawn|popen|capture2|capture3)$"
    case Languages.csharp => "(" + cmdSinks + ")|^(Start|Process\\.Start)$"
    case _ => cmdSinks
  }

  def pathSinksFor(language: String): String = language match {
    case Languages.python => "(" + pathSinks + ")|^(open|read_text|read_bytes|write_text|write_bytes|remove|unlink)$"
    case Languages.go => "(" + pathSinks + ")|^(Open|OpenFile|ReadFile|WriteFile|Create|Stat|Remove)$"
    case Languages.java => "(" + pathSinks + ")|^(readAllBytes|write|newInputStream|newOutputStream|FileInputStream|FileOutputStream)$"
    case Languages.php => "(" + pathSinks + ")|^(file_get_contents|file_put_contents|fopen|unlink|readfile)$"
    case Languages.ruby => "(" + pathSinks + ")|^(read|write|open|delete|unlink)$"
    case Languages.csharp => "(" + pathSinks + ")|^(ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Open|OpenRead|Delete|GetFullPath)$"
    case _ => pathSinks
  }

  def ssrfSinksFor(language: String): String = language match {
    case Languages.python =>
      "requests\\.(get|post|put|delete|request)|httpx\\.(get|post|put|delete|request)|urllib\\.request\\.(urlopen|Request)|^(urlopen)$"
    case Languages.go =>
      "http\\.(Get|Post|Head|NewRequest|NewRequestWithContext)|\\.[Dd]o\\("
    case Languages.java => "(" + ssrfSinks + ")|^(execute|getForObject|getForEntity|exchange|openConnection)$"
    case Languages.php => "(" + ssrfSinks + ")|^(curl_exec|file_get_contents|fopen)$"
    case Languages.ruby => "(" + ssrfSinks + ")|^(get|get_response|open|URI\\.open|Net::HTTP)$"
    case Languages.csharp => "(" + ssrfSinks + ")|^(GetAsync|PostAsync|SendAsync|GetStringAsync|WebRequest|Create)$"
    case _ => ssrfSinks
  }

  def xssSinksFor(language: String): String = language match {
    case Languages.php => "(" + xssSinks + ")|^(echo|print|printf)$"
    case Languages.ruby => "(" + xssSinks + ")|^(html_safe|raw|render|send_data)$"
    case Languages.csharp => "(" + xssSinks + ")|^(Write|WriteAsync|Content|HtmlRaw|Raw)$"
    case _ => xssSinks
  }
}

def regexMatches(value: String, pattern: String): Boolean = {
  if (value == null || value.isEmpty) return false
  try {
    value.matches(pattern) || value.matches(s"(?is).*($pattern).*")
  } catch {
    case _: Exception => false
  }
}

def callMatches(call: io.shiftleft.codepropertygraph.generated.nodes.Call, pattern: String): Boolean = {
  regexMatches(call.name, pattern) ||
  regexMatches(call.methodFullName, pattern) ||
  regexMatches(call.code, pattern)
}

def callsMatching(pattern: String) = cpg.call
  .filter(c => !c.name.startsWith("<operator>"))
  .filter(c => callMatches(c, pattern))

def sqlCalls(language: String) = callsMatching(Sinks.sqlSinksFor(language))
  .filter { call =>
    val code = call.code
    language match {
      case Languages.go =>
        !code.matches("(?is).*\\.URL\\.Query\\s*\\(.*")
      case Languages.python =>
        !code.matches("(?is).*request\\.(args|form|json|values|GET|POST)\\.(get|getlist)\\s*\\(.*")
      case _ => true
    }
  }

object Sanitizers {
  // Patterns are used with Joern .name() which applies Java regex.
  // Anchored with ^(...)$ to prevent partial matches (e.g. sanitizeForDisplay
  // matching as a SQL sanitizer) which cause true vulnerabilities to be dismissed.
  val sqlParameterization = "^(prepare|preparedStatement|bind|bindParam|bindValue|setString|setInt|setLong|placeholders?)$"
  val xssEncoding = "^(escapeHtml|htmlEscape|htmlEncode|encodeForHTML|DOMPurify|sanitizeHtml|HTMLEscapeString)$"
  // CAUTION: resolve is included for detection but is NOT a strong normalizer.
  // path.resolve(base, absoluteInput) returns absoluteInput directly.
  // verify-path.sc handles resolve separately from strong normalizers.
  val pathNormalization = "^(resolve|normalize|basename|realpath|filepath\\.Clean|path\\.Clean)$"
  val strongPathNormalization = "^(normalize|realpath|filepath\\.Clean|path\\.Clean)$"
  val weakPathNormalization = "^(resolve)$"
  val pathPrefixValidation = "^(startsWith|HasPrefix|contains|indexOf)$"
  val urlValidation = "^(URL|URI|urlparse|ParseRequestURI|validateUrl|allowlist|whitelist)$"
  val commandValidation = "^(allowlist|whitelist|matches|match|parseInt|parseFloat|Number|atoi)$"
  val xxeDisabling = "^(setFeature|setAttribute|defusedxml|libxml_disable_entity_loader|FEATURE_SECURE_PROCESSING)$"
  val deserSanitizers = "^(SafeLoader|safe_load|FullLoader|ObjectInputFilter|allowed_classes|json_decode)$"
  val ldapEscaping = "^(escape_filter_chars|ldap_escape|escape_dn_chars|filter_format|filterEncode|encodeForLDAP)$"
  val cryptoRandomness = "^(randomBytes|getRandomValues|SecureRandom|secrets|urandom|SystemRandom|VRFConsumerBase|requestRandomness|crypto)$"
}

object Confidence {
  // Confidence in VERIFIED verdict
  val VERIFIED_TAINT_WITH_CONCAT = 0.95
  val VERIFIED_TAINT_NO_SANITIZER = 0.90
  val VERIFIED_HEURISTIC = 0.75

  // Confidence in FALSE_POSITIVE verdict
  val FP_PARAMETERIZED_QUERY = 0.92
  val FP_SAFE_LOADER = 0.95
  val FP_TYPE_COERCION = 0.88
  val FP_NO_DATAFLOW = 0.80
  val FP_ENTITY_DISABLED = 0.92
  val FP_SANITIZER = 0.80

  // Confidence in NEEDS_REVIEW verdict
  val NR_PARTIAL_SANITIZER = 0.55
  val NR_WEAK_SANITIZER = 0.50
  val NR_CONTEXT_UNCLEAR = 0.40
}

def findAttackerFlows(sink: io.shiftleft.codepropertygraph.generated.nodes.Call, language: String, focus: String = "http"): List[io.shiftleft.codepropertygraph.generated.nodes.StoredNode] = {
  val paramSources = cpg.parameter.name(Sources.parameterPattern(language, focus))
  val fieldSources = cpg.fieldAccess.code(Sources.fieldPattern(language, focus))
  val callSources = cpg.call.name(Sources.callPattern(language, focus))
  val globalSources = cpg.identifier.name(Sources.globalAccessPattern(language))

  val paramFlows = try { sink.argument.reachableBy(paramSources).l } catch { case _: Exception => List.empty }
  val fieldFlows = try { sink.argument.reachableBy(fieldSources).l } catch { case _: Exception => List.empty }
  val callFlows = try { sink.argument.reachableBy(callSources).l } catch { case _: Exception => List.empty }
  val globalFlows = try { sink.argument.reachableBy(globalSources).l } catch { case _: Exception => List.empty }

  val directFlows = (paramFlows ++ fieldFlows ++ callFlows ++ globalFlows).distinct

  if (directFlows.nonEmpty) return directFlows

  // Workaround for Joern upstream bug: dataflow engine cannot chain through
  // local variable assignments in Python/Go (e.g. `query = request.args.get("q")`
  // then `db.execute(... + query + ...)`). We do a two-hop check:
  // 1. Find identifiers that reach the sink
  // 2. Check if any attacker source reaches those identifiers
  val sinkIdentifiers = try { sink.argument.reachableBy(cpg.identifier).l } catch { case _: Exception => List.empty }
  if (sinkIdentifiers.nonEmpty) {
    val twoHopFlows = sinkIdentifiers.filter { id =>
      val toId = try {
        (id.reachableBy(callSources).l ++ id.reachableBy(fieldSources).l ++ id.reachableBy(globalSources).l)
      } catch { case _: Exception => List.empty }
      toId.nonEmpty
    }
    if (twoHopFlows.nonEmpty) return twoHopFlows
  }

  // Last resort: heuristic text match on sink arguments
  if (sinkArgContainsUserInput(sink, language)) {
    // Return a synthetic marker so callers know there's a heuristic match
    return List(sink)
  }

  List.empty
}

case class VerificationResult(
  verdict: String,           // VERIFIED, FALSE_POSITIVE, NEEDS_REVIEW, NA_CPG
  confidence: Double,        // 0.0 - 1.0
  reason: String,
  dataFlow: Option[DataFlowPath] = None,
  sanitizers: List[String] = List.empty
)

case class DataFlowPath(
  sourceFile: String,
  sourceLine: Int,
  sourceCode: String,
  sinkFile: String,
  sinkLine: Int,
  sinkCode: String,
  path: List[String]
)

def isTestFile(fileName: String): Boolean = {
  fileName.contains("test") ||
  fileName.contains("spec") ||
  fileName.contains("mock") ||
  fileName.contains("__tests__") ||
  fileName.contains("fixtures")
}

def isVendorFile(fileName: String): Boolean = {
  fileName.contains("node_modules") ||
  fileName.contains("vendor") ||
  fileName.contains("third_party")
}

def shouldExclude(fileName: String): Boolean = {
  isTestFile(fileName) || isVendorFile(fileName)
}

def formatLocation(file: String, line: Int): String = s"$file:$line"

def toJson(result: VerificationResult): String = {
  val dataFlowJson = result.dataFlow.map { df =>
    s"""
    |  "dataFlow": {
    |    "source": {"file": "${df.sourceFile}", "line": ${df.sourceLine}, "code": "${escapeJson(df.sourceCode)}"},
    |    "sink": {"file": "${df.sinkFile}", "line": ${df.sinkLine}, "code": "${escapeJson(df.sinkCode)}"},
    |    "path": [${df.path.map(p => s""""${escapeJson(p)}"""").mkString(", ")}]
    |  },""".stripMargin
  }.getOrElse("")

  val sanitizersJson = if (result.sanitizers.nonEmpty) {
    s""""sanitizers": [${result.sanitizers.map(s => s""""$s"""").mkString(", ")}],"""
  } else ""

  s"""{
  |  "verdict": "${result.verdict}",
  |  "confidence": ${result.confidence},
  |  "reason": "${escapeJson(result.reason)}",
  |$dataFlowJson
  |$sanitizersJson
  |  "method": "joern-cpg"
  |}""".stripMargin.replaceAll("\n\\s*\n", "\n")
}

def escapeJson(s: String): String = {
  s.flatMap {
    case '\\' => "\\\\"
    case '"' => "\\\""
    case '\b' => "\\b"
    case '\f' => "\\f"
    case '\n' => "\\n"
    case '\r' => "\\r"
    case '\t' => "\\t"
    case c if c < ' ' || c > '~' => f"\\u${c.toInt}%04x"
    case c => c.toString
  }
}

def printResult(result: VerificationResult): Unit = {
  println(toJson(result))
}
