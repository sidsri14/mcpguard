/** CLI argument parsing and dispatch. */
import { RULES } from "./rules.js";
import { scan } from "./scanner.js";
import { formatHuman, formatJson, formatSarif } from "./format.js";

export const EXIT = { OK: 0, FINDINGS: 1, ERROR: 2 };

const HELP = `mcpguard — static security linter for MCP server configurations

Usage:
  mcpguard scan <path...> [options]
  mcpguard rules
  mcpguard --version
  mcpguard --help

Options:
  -f, --format <human|json|sarif>   Output format (default: human)
      --fail-on <high|medium|low>   Minimum severity that sets exit code 1 (default: high)
      --quiet                       Suppress human summary on stdout (still exits by severity)
  -h, --help                        Show this help
  -v, --version                     Show version

Examples:
  mcpguard scan ~/.claude.json
  mcpguard scan . --format sarif > mcpguard.sarif
  mcpguard scan config1.json config2.json --format json --fail-on medium
`;

function parseScan(args) {
  const inputs = [];
  let format = "human";
  let failOn = "high";
  let quiet = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-f" || a === "--format") {
      format = args[++i];
    } else if (a === "--fail-on") {
      failOn = args[++i];
    } else if (a === "--quiet") {
      quiet = true;
    } else if (a === "-h" || a === "--help") {
      return { help: true };
    } else if (!a.startsWith("-")) {
      inputs.push(a);
    }
  }
  return { inputs, format, failOn, quiet };
}

export function run(argv) {
  const [command, ...rest] = argv;

  if (!command || command === "-h" || command === "--help") {
    process.stdout.write(HELP);
    return EXIT.OK;
  }
  if (command === "-v" || command === "--version") {
    process.stdout.write("mcpguard 0.1.0\n");
    return EXIT.OK;
  }
  if (command === "rules") {
    process.stdout.write(
      RULES.map((r) => `${r.id}  ${r.severity.padEnd(6)}  ${r.title}\n      ${r.rationale}\n      fix: ${r.remediation}`).join("\n") + "\n"
    );
    return EXIT.OK;
  }
  if (command !== "scan") {
    process.stderr.write(`Unknown command: ${command}\n\n${HELP}`);
    return EXIT.ERROR;
  }

  const opts = parseScan(rest);
  if (opts.help) {
    process.stdout.write(HELP);
    return EXIT.OK;
  }
  if (!opts.inputs.length) {
    process.stderr.write("Error: scan requires at least one file or directory.\n\n" + HELP);
    return EXIT.ERROR;
  }
  if (!["human", "json", "sarif"].includes(opts.format)) {
    process.stderr.write(`Error: invalid format '${opts.format}'. Use human, json, or sarif.\n`);
    return EXIT.ERROR;
  }
  if (!["high", "medium", "low"].includes(opts.failOn)) {
    process.stderr.write(`Error: invalid --fail-on '${opts.failOn}'. Use high, medium, or low.\n`);
    return EXIT.ERROR;
  }

  const report = scan(opts.inputs);

  if (opts.format === "json") {
    process.stdout.write(formatJson(report) + "\n");
  } else if (opts.format === "sarif") {
    process.stdout.write(formatSarif(report) + "\n");
  } else if (!opts.quiet) {
    process.stdout.write(formatHuman(report) + "\n");
  }

  if (report.errors.length && !report.findings.length) return EXIT.ERROR;

  const threshold = { high: 0, medium: 1, low: 2 }[opts.failOn];
  const triggered = report.findings.some(
    (f) => ({ HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 }[f.severity] ?? 3) <= threshold
  );
  return triggered ? EXIT.FINDINGS : EXIT.OK;
}
