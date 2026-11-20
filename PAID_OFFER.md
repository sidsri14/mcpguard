# MCP Configuration Security Review — proposed paid offer

**Status: PROPOSED. Not income. No payment received. Requires explicit approval before any external send.**

This document ties the `mcpguard` OSS tool to a paid, tightly-scoped service. It exists so the OSS work is directly connected to a revenue path rather than being an unpaid portfolio item.

## Live proof

- Tool source: https://github.com/sidsri14/mcpguard (CI green on Node 20/22/24)
- Landing page: https://sidsri14.github.io/mcpguard/
- Sample review report (generated from a real scan): https://sidsri14.github.io/mcpguard/sample-report.html
- Test suite: `npm test` — 11/11 passing, zero runtime dependencies

## Service

**MCP Configuration Security Review** — a static review of a customer's MCP client/server configuration files using `mcpguard`, plus a human-written remediation report.

### Deliverables (fixed scope)

1. Run `mcpguard` over the customer-supplied config files (`claude_desktop_config.json`, `.mcp.json`, Cursor/VS Code configs, or a repo containing them).
2. A written report listing each finding: rule ID, severity, exact file/field, why it matters, and a concrete fix.
3. A corrected example config (diff) for the issues found, with secrets replaced by environment-variable references.
4. A SARIF file suitable for upload to GitHub code scanning, if the customer wants CI gating.
5. One follow-up pass after the customer applies fixes, to confirm findings are resolved.

### Out of scope (explicit)

- No code execution, no penetration testing, no exploitation, no live target testing.
- No review of MCP server source code — configuration files only.
- No secret rotation, credential handling, or access to the customer's live systems.
- No guarantee of "fully secure"; the report covers the eight documented rules and static inspection only.
- No tax, legal, or compliance advice.

### Proposed pricing (NOT received, NOT agreed with any buyer)

| Tier | Scope | Proposed price |
|---|---|---|
| Single review | Up to 5 config files, report + corrected examples + one recheck | USD $150 |
| Team review | Up to 20 config files, SARIF + CI setup guidance + one recheck | USD $350 |

These are ask prices for a future buyer. They are not booked revenue, not an invoice, and not a claim that anyone has accepted them. Adjust only with user approval.

### Payout boundary

- Bank transfer or PayPal **only** (PayPal payout account: `sidsri1302@gmail.com`).
- No crypto, no wallet, no voucher, no escrow funding by the assistant.
- No spending, no platform fee payment, no tax attestation made by the assistant.

### Truthful seller qualification (use verbatim or not at all)

> I'm Siddharth, an independent developer and BCA candidate (expected 2027). I built `mcpguard`, an open-source, zero-dependency static linter for MCP configurations, with 8 documented rules and a test suite. I'm offering a fixed-scope static config review — no live testing, no source-code audit. I'll show the tool's source and test results before you pay.

Do **not** claim: years of professional security experience, production deployments, penetration-testing certifications, named enterprise customers, or a number of "vulnerabilities found" that cannot be shown.

## Where to offer (requires approval; daily first-contact cap applies)

- Freelancer: a fixed-price project bid on an MCP/AI-agent security review request, only if a real buyer exists.
- Direct outreach only to parties who have an actual need; no unsolicited mass email.
- Do not post to Fiverr without a real on-platform order and agreed payment.

## README truth cross-check

All tool capabilities claimed here are implemented in `src/` and covered by `npm test`. No benchmark numbers, no production claims.
