/**
 * Kuzushi module wrapper for vuln-scout.
 * Exposes whitebox pentesting commands as ModuleTools.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const COMMANDS_DIR = join(__dirname, "whitebox-pentest", "commands");
const PACKAGE_JSON = JSON.parse(readFileSync(join(__dirname, "package.json"), "utf-8"));
const PACKAGE_VERSION = PACKAGE_JSON.version;

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
          systemPrompt: "You are a security researcher performing whitebox penetration testing.",
          tools: ["Read", "Glob", "Grep", "Bash"],
        })) {
          if (msg.type === "result") text = msg.text ?? text;
          else if (msg.type === "assistant" && msg.content) {
            for (const block of msg.content) {
              if (block.type === "text") text += block.text;
            }
          }
        }
        return { ok: true, output: text || "Analysis complete." };
      } catch (err) {
        return { ok: false, output: `VulnScout error: ${err.message ?? err}` };
      }
    },
  };
}

export default {
  id: "vuln-scout",
  displayName: "VulnScout Whitebox Pentesting",
  category: "offense",
  version: PACKAGE_VERSION,
  description:
    "AI-powered whitebox pentesting with Semgrep, Joern CPG, CodeQL. " +
    "9-language support, STRIDE modeling, evidence-first findings.",
  tools: [
    createTool("full-audit", "vuln-scout:audit",
      "Run a full whitebox security audit — scoping, threat modeling, scanning, verification, and reporting.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
        },
        required: ["target"],
      }),
    createTool("scan", "vuln-scout:scan",
      "Run Semgrep + Joern CPG scanning on the target.",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
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
    createTool("auto-fix", "vuln-scout:fix",
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
      "Generate a security assessment report (SARIF + Markdown).",
      {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          format: { type: "string", enum: ["sarif", "md", "json"], description: "Report format." },
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
