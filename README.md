# mcpguard

> Static security linter for Model Context Protocol (MCP) server configurations.

`mcpguard` reads MCP client configuration files (Claude Desktop, Cursor, VS Code, Windsurf, and any JSON with an `mcpServers` / `servers` key) and flags risky patterns before they reach an agent runtime. Zero runtime dependencies, Node 20+, CI-friendly, SARIF output.

## Why

MCP configs are code. They commonly contain:

- `npx -y package@latest` — non-interactive install of whatever is published today (supply-chain risk)
- literal API keys and tokens in `env` and `args` — leaked via dotfile commits, process listings, shell history
- `sh -c` wrappers and `--no-sandbox` flags — injected command execution and removed isolation
- `http://` remote endpoints — cleartext tool calls
- `allowedTools: ["*"]` — no least-privilege boundary

These are static, checkable properties. `mcpguard` checks them.

## Install

```bash
npm install -g mcpguard
```

Or run from a checkout with no install step:

```bash
node bin/mcpguard.js scan ~/.claude.json
```

## Usage

```bash
# Scan a single config
mcpguard scan ~/.claude.json

# Scan a directory tree (skips node_modules, .git, dist, etc.)
mcpguard scan . --format sarif > mcpguard.sarif

# Machine-readable report, fail CI on medium+ findings
mcpguard scan configs/ --format json --fail-on medium

# List all rules
mcpguard rules

mcpguard --version
mcpguard --help
```

### Options

| Flag | Default | Meaning |
|---|---|---|
| `-f, --format <human\|json\|sarif>` | `human` | Output format |
| `--fail-on <high\|medium\|low>` | `high` | Minimum severity that sets exit code `1` |
| `--quiet` | off | Suppress human stdout (exit code still applies) |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on`, and no parse errors |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage error, or parse errors with no findings |

## Rules

| ID | Severity | Detects |
|---|---|---|
| `MCP001` | HIGH | Unpinned package spec (`@latest`, ranges, no version) with `-y`/`dlx` |
| `MCP002` | HIGH | Hardcoded credential in `env` (GitHub, AWS, Slack, Google, OpenAI-style, JWT, private key, or key-name heuristic) |
| `MCP003` | MEDIUM | Filesystem-style server granted a broad root (`/`, drive root, home dir) |
| `MCP004` | HIGH | Shell delegation (`sh -c`, `bash -c`, `cmd /c`, PowerShell `-enc`, `eval`, `exec`) |
| `MCP005` | HIGH | Security control disabled (`--no-sandbox`, `--insecure`, `--disable-web-security`, …) |
| `MCP006` | MEDIUM | Cleartext `http://` remote MCP endpoint to a non-loopback host |
| `MCP007` | MEDIUM | Wildcard tool permission (`*` / `all` in allowlists) |
| `MCP008` | HIGH | Hardcoded credential embedded in a command-line argument |

Secret values are **masked** in all output — reports never print the full credential.

## SARIF / GitHub code scanning

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 20
- name: Scan MCP configs
  run: node bin/mcpguard.js scan . --format sarif > mcpguard.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcpguard.sarif
```

## Scope and non-claims

`mcpguard` is a **static configuration linter**. It:

- parses JSON only and does not execute commands or connect to servers;
- detects documented patterns in configuration strings, not arbitrary vulnerabilities;
- reports approximate line/column positions (masked values and parsed values may fall back to line 1);
- does not verify package integrity, signature, or maintainer trust at install time;
- does not scan running processes, network traffic, or source code of MCP servers;
- is not a substitute for a security review, sandboxing, or a secret manager.

A clean scan means "none of these eight patterns were found," not "this configuration is secure."

## Development

```bash
npm test
```

Tests use Node's built-in `node:test` runner — no dev dependencies.

## License

MIT © 2026 Siddharth Srivastava
