/** Output formatters. */

const LEVEL = { HIGH: "error", MEDIUM: "warning", LOW: "note", INFO: "note" };

function shortSeverity(sev) {
  return sev.padEnd(6);
}

/** Human-readable colored/plain report. */
export function formatHuman(report) {
  const lines = [];
  lines.push("mcpguard v" + report.tool.version + " — MCP config security scan");
  lines.push("Scanned " + report.scannedFiles + " file(s); " + report.configFiles + " MCP config(s).");
  lines.push("");
  if (report.errors.length) {
    lines.push("Parse errors:");
    for (const e of report.errors) lines.push("  ! " + e.file + ": " + e.error);
    lines.push("");
  }
  if (!report.findings.length) {
    lines.push("No findings.");
    return lines.join("\n");
  }
  lines.push(
    `Findings: ${report.counts.HIGH} high, ${report.counts.MEDIUM} medium, ` +
      `${report.counts.LOW} low, ${report.counts.INFO} info`
  );
  lines.push("");
  let lastFile = null;
  for (const f of report.findings) {
    if (f.file !== lastFile) {
      lines.push("  " + f.file);
      lastFile = f.file;
    }
    lines.push(`  [${shortSeverity(f.severity)}] ${f.ruleId}  ${f.server} :: ${f.field}`);
    lines.push(`      ${f.message}`);
    lines.push(`      fix: ${f.remediation}`);
    lines.push(`      at line ${f.startLine}, column ${f.startColumn}`);
  }
  return lines.join("\n");
}

export function formatJson(report) {
  return JSON.stringify(report, null, 2);
}

/** SARIF 2.1.0 — uploadable to GitHub code scanning. */
export function formatSarif(report) {
  const usedRules = [...new Set(report.findings.map((f) => f.ruleId))].sort();
  const ruleMeta = new Map();
  for (const f of report.findings) {
    if (!ruleMeta.has(f.ruleId)) {
      ruleMeta.set(f.ruleId, {
        id: f.ruleId,
        name: f.title.replace(/[^A-Za-z0-9]/g, ""),
        shortDescription: { text: f.title },
        fullDescription: { text: f.rationale },
        defaultConfiguration: { level: LEVEL[f.severity] || "warning" },
        help: { text: f.remediation },
        properties: { tags: ["security", "mcp", "static-analysis"] }
      });
    }
  }
  const results = report.findings.map((f) => ({
    ruleId: f.ruleId,
    level: LEVEL[f.severity] || "warning",
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file.replace(/\\/g, "/") },
          region: { startLine: f.startLine, startColumn: f.startColumn }
        }
      }
    ],
    properties: {
      server: f.server,
      field: f.field,
      sourceKey: f.sourceKey,
      severity: f.severity
    }
  }));

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: report.tool.name,
              version: report.tool.version,
              informationUri: "https://github.com/sidsri14/mcpguard",
              rules: usedRules.map((id) => ruleMeta.get(id)).filter(Boolean)
            }
          },
          results
        }
      ]
    },
    null,
    2
  );
}
