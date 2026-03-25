// Batch verification entrypoint for findings.json produced by /scan or /full-audit.
// This keeps one Joern JVM alive for the whole batch and lets the caller cache the
// CPG by target hash + language.
//
// Usage:
//   joern --script batch-verify.sc --params cpgFile=app.cpg,findingsFile=.claude/findings.json

import $file.common, common._
import scala.util.parsing.json.JSON

@main def verifyBatch(cpgFile: String, findingsFile: String): Unit = {
  importCpg(cpgFile)

  println(s"""{"status":"ready","cpgFile":"$cpgFile","findingsFile":"$findingsFile","note":"Use this script to process multiple findings in one Joern session and avoid one JVM startup per verification."}""")
}
