import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan, scanFile, expandInputs } from "../src/scanner.js";
import { formatSarif, formatJson, formatHuman } from "../src/format.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(here, "fixtures", name);

test("detects expected findings in a bad config", () => {
  const result = scanFile(fixture("bad-config.json"));
  assert.equal(result.error, null);
  assert.equal(result.hasConfig, true);
  const ids = result.findings.map((f) => f.ruleId);
  for (const id of ["MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP006", "MCP007", "MCP008"]) {
    assert.ok(ids.includes(id), `expected ${id}, got ${ids.join(",")}`);
  }
});

test("good config has no findings", () => {
  const result = scanFile(fixture("good-config.json"));
  assert.equal(result.error, null);
  assert.deepEqual(result.findings, []);
});

test("non-MCP config is ignored", () => {
  const result = scanFile(fixture("not-a-config.json"));
  assert.equal(result.hasConfig, false);
  assert.deepEqual(result.findings, []);
});

test("secret values are masked in findings", () => {
  const result = scanFile(fixture("bad-config.json"));
  const tokenFinding = result.findings.find((f) => f.ruleId === "MCP002");
  assert.ok(tokenFinding);
  assert.ok(!tokenFinding.value.includes("abcdefghijklmnopqrstuvwxyz0123456789"));
  assert.ok(tokenFinding.value.startsWith("ghp_"));
  assert.ok(tokenFinding.value.includes("************"));
});

test("cleartext remote and loopback are distinguished", () => {
  const bad = scanFile(fixture("bad-config.json"));
  assert.ok(bad.findings.some((f) => f.ruleId === "MCP006"));

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpguard-"));
  const file = path.join(dir, "loopback.json");
  fs.writeFileSync(file, JSON.stringify({ mcpServers: { local: { url: "http://127.0.0.1:8080/mcp" } } }));
  const result = scanFile(file);
  assert.ok(!result.findings.some((f) => f.ruleId === "MCP006"));
  fs.rmSync(dir, { recursive: true, force: true });
});

test("findings are sorted by severity", () => {
  const result = scan([fixture("bad-config.json")]);
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  for (let i = 1; i < result.findings.length; i++) {
    assert.ok(order[result.findings[i - 1].severity] <= order[result.findings[i].severity]);
  }
  assert.equal(result.counts.HIGH, 6);
  assert.equal(result.counts.MEDIUM, 3);
});

test("expandInputs expands directories and de-duplicates", () => {
  const files = expandInputs([path.join(here, "fixtures"), fixture("bad-config.json")]);
  assert.ok(files.length >= 3);
  assert.equal(new Set(files).size, files.length);
});

test("JSON formatter is valid JSON with report fields", () => {
  const report = scan([fixture("bad-config.json")]);
  const parsed = JSON.parse(formatJson(report));
  assert.equal(parsed.tool.name, "mcpguard");
  assert.ok(Array.isArray(parsed.findings));
});

test("SARIF formatter is valid SARIF 2.1.0", () => {
  const report = scan([fixture("bad-config.json")]);
  const sarif = JSON.parse(formatSarif(report));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, "mcpguard");
  assert.equal(sarif.runs[0].results.length, report.findings.length);
  const levels = new Set(sarif.runs[0].results.map((r) => r.level));
  assert.ok(levels.has("error") && levels.has("warning"));
  assert.ok(sarif.runs[0].tool.driver.rules.length >= 8);
});

test("human formatter includes summary and remediation", () => {
  const report = scan([fixture("bad-config.json")]);
  const out = formatHuman(report);
  assert.match(out, /mcpguard v0\.1\.0/);
  assert.match(out, /Findings:/);
  assert.match(out, /fix:/);
});

test("invalid JSON produces an error, not a crash", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpguard-"));
  const file = path.join(dir, "broken.json");
  fs.writeFileSync(file, "{ this is not json");
  const result = scanFile(file);
  assert.match(result.error, /Could not parse JSON/);
  assert.deepEqual(result.findings, []);
  fs.rmSync(dir, { recursive: true, force: true });
});
