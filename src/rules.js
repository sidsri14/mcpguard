/** Rule definitions. Each check(ctx) returns an array of findings. */
import {
  classifySecret,
  findDisableFlags,
  findWildcardPermissions,
  isBroadRoot,
  isCleartextRemote,
  isDangerousShell,
  isExactVersion,
  maskSecret,
  splitPackageSpec
} from "./util.js";

const RUNNER_PACKAGES = {
  npx: { flagsFirst: true },
  bunx: { flagsFirst: true },
  uvx: { flagsFirst: true },
  pnpm: { subcommand: "dlx" },
  yarn: { subcommand: "dlx" }
};

/**
 * @typedef {object} RuleContext
 * @property {string} file
 * @property {string} serverName
 * @property {object} server
 * @property {string} raw
 */

function firstNonFlag(args) {
  for (const arg of args) {
    if (typeof arg === "string" && !arg.startsWith("-")) return arg;
  }
  return null;
}

export const RULES = [
  {
    id: "MCP001",
    severity: "HIGH",
    title: "Unpinned package spec",
    rationale:
      "Fetching a package without an exact version pin means the code that runs can change between starts. With npx -y / dlx this happens non-interactively.",
    remediation: "Pin an exact version, e.g. @modelcontextprotocol/server-filesystem@2026.7.1.",
    check({ server }) {
      const findings = [];
      const command = typeof server.command === "string" ? server.command.split(/[\\/]/).pop().toLowerCase() : "";
      const runner = RUNNER_PACKAGES[command];
      if (!runner || !Array.isArray(server.args)) return findings;

      let args = server.args;
      if (runner.subcommand) {
        const idx = args.findIndex((a) => typeof a === "string" && a.toLowerCase() === runner.subcommand);
        if (idx === -1) return findings;
        args = args.slice(idx + 1);
      }
      const spec = firstNonFlag(args);
      if (!spec) return findings;
      // Scoped packages (@scope/name) contain '/', so only treat clear path forms as local.
      const looksLocal =
        spec.startsWith(".") ||
        spec.startsWith("/") ||
        spec.startsWith("~") ||
        /^[A-Za-z]:[\\/]/.test(spec) ||
        (!spec.startsWith("@") && spec.includes("/"));
      if (looksLocal) return findings;
      const { name, version } = splitPackageSpec(spec);
      if (!name) return findings;
      if (isExactVersion(version)) return findings;

      const autoYes = args.some((a) => a === "-y" || a === "--yes");
      findings.push({
        field: "args",
        value: spec,
        message: `Package '${name}' is not pinned to an exact version${version ? ` (found '${version}')` : ""}${autoYes ? " and is auto-installed with -y/--yes" : ""}.`
      });
      return findings;
    }
  },
  {
    id: "MCP002",
    severity: "HIGH",
    title: "Hardcoded credential in environment",
    rationale:
      "Secrets placed in a client config are commonly committed to dotfiles/repos and are visible to every process that can read the config.",
    remediation: "Reference an environment variable instead, e.g. ${GITHUB_TOKEN} or env:GITHUB_TOKEN.",
    check({ server }) {
      const findings = [];
      const env = server.env;
      if (!env || typeof env !== "object" || Array.isArray(env)) return findings;
      for (const [key, value] of Object.entries(env)) {
        const secret = classifySecret(value, key);
        if (!secret) continue;
        findings.push({
          field: `env.${key}`,
          value: maskSecret(value),
          message: `${secret.kind} assigned to '${key}'.`
        });
      }
      return findings;
    }
  },
  {
    id: "MCP003",
    severity: "MEDIUM",
    title: "Over-broad filesystem root",
    rationale:
      "Granting a filesystem server '/', a drive root, or the home directory as an allowed root exposes every readable/writable file to the agent.",
    remediation: "Scope the server to the smallest project directory it actually needs.",
    check({ serverName, server }) {
      const findings = [];
      const label = `${serverName} ${server.command || ""} ${(server.args || []).join(" ")}`.toLowerCase();
      if (!/(filesystem|desktop-commander|file.?system|\bgit\b|\bfiles\b)/.test(label)) return findings;
      if (!Array.isArray(server.args)) return findings;
      for (let i = 0; i < server.args.length; i++) {
        const value = server.args[i];
        if (isBroadRoot(value)) {
          findings.push({
            field: `args[${i}]`,
            value,
            message: `Filesystem-style server is granted broad root '${value}'.`
          });
        }
      }
      return findings;
    }
  },
  {
    id: "MCP004",
    severity: "HIGH",
    title: "Dangerous shell delegation",
    rationale:
      "Commands that pass arguments through sh -c / bash -c / cmd /c expand strings into a shell, turning config values into an injection surface.",
    remediation: "Invoke the target binary directly with a structured argument array; avoid shell -c wrappers.",
    check({ server }) {
      const parts = [server.command, ...(Array.isArray(server.args) ? server.args : [])];
      const joined = parts.filter((p) => typeof p === "string").join(" ");
      if (!isDangerousShell(joined)) return [];
      return [
        {
          field: "command",
          value: String(server.command || ""),
          message: "Command delegates to a shell interpreter (-c / /c / -enc) or uses eval/exec."
        }
      ];
    }
  },
  {
    id: "MCP005",
    severity: "HIGH",
    title: "Security control disabled",
    rationale:
      "Flags such as --no-sandbox or --disable-web-security remove isolation or transport protections from the server process.",
    remediation: "Remove the flag. If a sandbox conflict occurs, fix the underlying cause rather than disabling the control.",
    check({ server }) {
      const findings = [];
      const parts = [server.command, ...(Array.isArray(server.args) ? server.args : [])];
      for (let i = 0; i < parts.length; i++) {
        for (const flag of findDisableFlags(parts[i])) {
          findings.push({
            field: i === 0 ? "command" : `args[${i - 1}]`,
            value: flag,
            message: `Security-disabling flag '${flag}' is present.`
          });
        }
      }
      return findings;
    }
  },
  {
    id: "MCP006",
    severity: "MEDIUM",
    title: "Cleartext remote transport",
    rationale:
      "An http:// remote MCP endpoint sends tool calls and results without TLS, exposing them to interception on the path.",
    remediation: "Use an https:// URL (or a loopback address for strictly local development).",
    check({ server }) {
      if (!isCleartextRemote(server.url)) return [];
      return [
        {
          field: "url",
          value: server.url,
          message: "Remote MCP server uses cleartext HTTP to a non-loopback host."
        }
      ];
    }
  },
  {
    id: "MCP007",
    severity: "MEDIUM",
    title: "Wildcard tool permission",
    rationale:
      "A '*' / 'all' allowlist grants the agent every tool the server exposes, removing the benefit of least privilege.",
    remediation: "List only the specific tool names the workflow requires.",
    check({ server }) {
      return findWildcardPermissions(server).map((p) => ({
        field: p.field,
        value: p.value,
        message: `Wildcard tool permission at '${p.field}'.`
      }));
    }
  },
  {
    id: "MCP008",
    severity: "HIGH",
    title: "Hardcoded credential in arguments",
    rationale:
      "Command-line arguments are visible in process listings and are frequently captured by shell history and crash logs.",
    remediation: "Pass the credential via an environment variable reference instead of a literal argument.",
    check({ server }) {
      const findings = [];
      const args = Array.isArray(server.args) ? server.args : [];
      const SECRET_ARG_RE = /^(--?token|--?api[_-]?key|--?password|--?secret|--?auth)([=:])(.+)$/i;
      for (let i = 0; i < args.length; i++) {
        const value = args[i];
        if (typeof value !== "string") continue;
        const m = value.match(SECRET_ARG_RE);
        const candidate = m ? m[3] : null;
        const secret = candidate ? classifySecret(candidate, "token") : classifySecret(value, "");
        if (secret) {
          findings.push({
            field: `args[${i}]`,
            value: maskSecret(m ? candidate : value),
            message: `${secret.kind} embedded in command-line argument.`
          });
        }
      }
      return findings;
    }
  }
];

export const SEVERITY_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
