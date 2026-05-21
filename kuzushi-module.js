/**
 * Kuzushi module wrapper for vuln-scout.
 * Exposes whitebox security review commands as ModuleTools.
 */

import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const COMMANDS_DIR = join(__dirname, "vuln-scout", "commands");
const PACKAGE_JSON = JSON.parse(readFileSync(join(__dirname, "package.json"), "utf-8"));
const PACKAGE_VERSION = PACKAGE_JSON.version;

const TOOL_MATURITY = {
  "vuln-scout:full-audit": "stable",
  "vuln-scout:verify": "stable",
  "vuln-scout:report": "stable",
  "vuln-scout:scope": "stable",
  "vuln-scout:diff": "stable",
  "vuln-scout:scan": "beta",
  "vuln-scout:threats": "beta",
  "vuln-scout:sinks": "beta",
  "vuln-scout:trace": "beta",
  "vuln-scout:propagate": "beta",
  "vuln-scout:create-rule": "experimental",
  "vuln-scout:org-memory-compile": "experimental",
  "vuln-scout:mutate": "experimental",
  "vuln-scout:auto-fix": "experimental",
};

function loadCommand(name) {
  const commandPath = join(COMMANDS_DIR, `${name}.md`);
  return readFileSync(commandPath, "utf-8");
}

function buildPrompt(commandPrompt, params, target) {
  const extraParams = Object.fromEntries(
    Object.entries(params).filter(([key]) => key !== "target"),
  );
  const paramsText = Object.keys(extraParams).length
    ? `\n\nParameters:\n${JSON.stringify(extraParams, null, 2)}`
    : "";
  return `${commandPrompt}\n\nTarget: ${target}${paramsText}`.trim();
}

function collectArtifacts(target, params) {
  const claudeDir = join(target, ".claude");
  const artifacts = {};
  for (const [key, rel] of [
    ["findings", "findings.json"],
    ["audit_plan", "audit-plan.md"],
    ["review_ledger", "review-ledger.json"],
    ["threat_model", "threat-model.md"],
  ]) {
    const p = join(claudeDir, rel);
    if (existsSync(p)) artifacts[key] = p;
  }
  if (params.output && existsSync(params.output)) artifacts.report = params.output;
  return artifacts;
}

function createTool(cmdName, toolName, description, inputSchema) {
  const commandPrompt = loadCommand(cmdName);
  return {
    name: toolName,
    description,
    inputSchema,
    headless: true,
    async execute(input, ctx) {
      const params = input ?? {};
      const target = params.target ?? ctx.target ?? ".";
      const prompt = buildPrompt(commandPrompt, params, target);

      try {
        let text = "";
        for await (const msg of ctx.runtime.query(prompt, {
          systemPrompt: "You are a security researcher performing whitebox security review.",
          tools: ["Read", "Glob", "Grep", "Bash"],
        })) {
          if (msg.type === "result") text = msg.text ?? text;
          else if (msg.type === "assistant" && msg.content) {
            for (const block of msg.content) {
              if (block.type === "text") text += block.text;
            }
          }
        }
        return {
          ok: true,
          output: text || "Analysis complete.",
          artifacts: collectArtifacts(target, params),
          maturity: TOOL_MATURITY[toolName],
          toolName,
        };
      } catch (err) {
        return {
          ok: false,
          output: `VulnScout error: ${err.message ?? err}`,
          artifacts: collectArtifacts(target, params),
          maturity: TOOL_MATURITY[toolName],
          toolName,
        };
      }
    },
  };
}

export default {
  id: "vuln-scout",
  displayName: "VulnScout Security Review",
  category: "security-review",
  version: PACKAGE_VERSION,
  description:
    "AI-assisted whitebox security review with deterministic quick scans, " +
    "STRIDE modeling, evidence-first findings, and portable reports.",
  tools: [
    createTool("full-audit", "vuln-scout:full-audit",
      "Run a full whitebox security audit — scoping, threat modeling, scanning, verification, and reporting.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          profile: { type: "string", enum: ["quick", "deep", "audit"], description: "Scan profile for the automated scan phase." },
          minSeverity: { type: "string", enum: ["critical", "high", "medium", "low", "info"], description: "Minimum severity to prioritize in the audit." },
          suppressions: { type: "string", description: "Path to a .vuln-scout-ignore suppression file." },
          failOn: { type: "string", enum: ["critical", "high", "medium", "low", "info"], description: "Fail the workflow when unsuppressed findings meet or exceed this severity." },
          sinceCommit: { type: "string", description: "Limit analysis to changes since this commit or ref." },
          workspace: { type: "string", description: "Optional workspace/module under the target path." },
          noInteractive: { type: "boolean", description: "Run without interactive approval prompts." },
        },
        required: ["target"],
      }),
    createTool("scan", "vuln-scout:scan",
      "Run Semgrep + Joern CPG scanning on the target.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          profile: { type: "string", enum: ["quick", "deep", "audit"], description: "Scan profile." },
          failOn: { type: "string", enum: ["critical", "high", "medium", "low", "info"], description: "Exit non-zero when unsuppressed findings meet or exceed this severity." },
          suppressions: { type: "string", description: "Path to a .vuln-scout-ignore suppression file." },
          sinceCommit: { type: "string", description: "Limit analysis to changes since this commit or ref." },
          workspace: { type: "string", description: "Optional workspace/module under the target path." },
          format: { type: "string", enum: ["json", "sarif", "md", "html", "pr-comment", "badge"], description: "Output format." },
          output: { type: "string", description: "Output file path." },
        },
        required: ["target"],
      }),
    createTool("trace", "vuln-scout:trace",
      "Trace data flows from sources to sinks for a specific vulnerability.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          finding: { type: "string", description: "Finding ID or description to trace." },
        },
        required: ["target"],
      }),
    createTool("verify", "vuln-scout:verify",
      "Verify a finding using CPG analysis and dynamic testing.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          finding: { type: "string", description: "Finding ID to verify." },
        },
        required: ["target"],
      }),
    createTool("sinks", "vuln-scout:sinks",
      "Hunt for dangerous function calls and security-sensitive sinks.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
        },
        required: ["target"],
      }),
    createTool("auto-fix", "vuln-scout:auto-fix",
      "Generate security patches for confirmed vulnerabilities.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          finding: { type: "string", description: "Finding ID to fix." },
        },
        required: ["target"],
      }),
    createTool("report", "vuln-scout:report",
      "Generate a security assessment report, PR comment, or evidence bundle.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          format: { type: "string", enum: ["sarif", "md", "json", "html", "pr-comment", "bundle"], description: "Report format. bundle writes a directory with findings.json, findings.sarif, vex.json, attestation.json, report.html, and README.md." },
          output: { type: "string", description: "Output file path, or required directory path when format is bundle." },
          suppressions: { type: "string", description: "Path to a .vuln-scout-ignore suppression file." },
          failOn: { type: "string", enum: ["critical", "high", "medium", "low", "info"], description: "Fail when unsuppressed findings meet or exceed this severity." },
        },
        required: ["target"],
      }),
    createTool("threats", "vuln-scout:threats",
      "Build a STRIDE threat model and identify high-risk attack surfaces.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
        },
        required: ["target"],
      }),
    createTool("scope", "vuln-scout:scope",
      "Create a focused audit scope for large repositories and monorepos.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          workspace: { type: "string", description: "Optional workspace/module name." },
        },
        required: ["target"],
      }),
    createTool("propagate", "vuln-scout:propagate",
      "Find related instances of a confirmed vulnerability pattern.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          pattern: { type: "string", description: "Finding location, rule, or pattern to propagate." },
        },
        required: ["target"],
      }),
    createTool("diff", "vuln-scout:diff",
      "Compare security posture between git references.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          baseRef: { type: "string", description: "Base git reference." },
          headRef: { type: "string", description: "Head git reference." },
          failOn: { type: "string", enum: ["critical", "high", "medium", "low", "info"], description: "Fail when changed findings meet or exceed this severity." },
        },
        required: ["target"],
      }),
    createTool("create-rule", "vuln-scout:create-rule",
      "Generate a custom Semgrep rule from a confirmed vulnerability pattern.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          finding: { type: "string", description: "Finding ID, location, or vulnerability pattern." },
        },
        required: ["target"],
      }),
    createTool("org-memory-compile", "vuln-scout:org-memory-compile",
      "Compile human-reviewed scan history into local organization memory.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          privacy: { type: "string", enum: ["open", "hashed", "strict"], description: "Org memory privacy mode." },
          dryRun: { type: "boolean", description: "Print proposed memory without writing files." },
        },
        required: ["target"],
      }),
    createTool("mutate", "vuln-scout:mutate",
      "Run security mutation testing to expose scanner detection gaps.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
        },
        required: ["target"],
      }),
  ],
};
