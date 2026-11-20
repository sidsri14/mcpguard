/** Shared helpers for mcpguard rules and formatters. */

const SERVER_KEYS = ["mcpServers", "servers", "mcp_servers"];

/** Extract the server map from a parsed config document. */
export function getServers(doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  for (const key of SERVER_KEYS) {
    const value = doc[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return { sourceKey: key, servers: value };
    }
  }
  return null;
}

/** Known credential prefixes. Matched before generic entropy checks. */
export const SECRET_PATTERNS = [
  { name: "GitHub token", re: /^gh[pousr]_[A-Za-z0-9]{20,}$/ },
  { name: "OpenAI-style key", re: /^sk-[A-Za-z0-9_-]{20,}$/ },
  { name: "AWS access key", re: /^AKIA[0-9A-Z]{16}$/ },
  { name: "Slack token", re: /^xox[baprs]-[A-Za-z0-9-]{10,}$/ },
  { name: "Google API key", re: /^AIza[A-Za-z0-9_-]{30,}$/ },
  { name: "JWT", re: /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/ },
  { name: "Private key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ }
];

const SECRET_KEY_RE = /token|secret|password|passwd|api[_-]?key|credential|private[_-]?key|auth/i;

/** True when a key name suggests it holds a credential. */
export function isSecretKey(key) {
  return typeof key === "string" && SECRET_KEY_RE.test(key);
}

/** True when a value looks like an environment-variable reference, not a literal. */
export function isEnvReference(value) {
  if (typeof value !== "string") return false;
  const v = value.trim();
  return (
    /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v) ||
    /^\{\{[^}]+\}\}$/.test(v) ||
    /^process\.env\.[A-Za-z_][A-Za-z0-9_]*$/.test(v) ||
    /^env:[A-Za-z_][A-Za-z0-9_]*$/i.test(v) ||
    /^<[^>]+>$/.test(v)
  );
}

/** Determine whether a value is a likely hardcoded credential. */
export function classifySecret(value, keyName = "") {
  if (typeof value !== "string" || isEnvReference(value)) return null;
  for (const p of SECRET_PATTERNS) {
    if (p.re.test(value)) return { kind: p.name, generic: false };
  }
  if (isSecretKey(keyName)) {
    const v = value.trim();
    if (v.length >= 16 && !/\s/.test(v)) {
      return { kind: "possible hardcoded credential (key name suggests secret)", generic: true };
    }
  }
  return null;
}

/** Mask a secret for safe display in reports. */
export function maskSecret(value) {
  if (typeof value !== "string") return String(value);
  if (value.length <= 8) return "*".repeat(value.length);
  const tail = Math.min(4, Math.max(0, value.length - 8));
  return `${value.slice(0, 4)}${"*".repeat(12)}${value.slice(-tail)}`;
}

/** Split a package spec into name and version (scoped packages handled). */
export function splitPackageSpec(spec) {
  if (typeof spec !== "string" || !spec) return { name: spec || "", version: null };
  const start = spec.startsWith("@") ? 1 : 0;
  const at = spec.indexOf("@", start);
  if (at === -1) return { name: spec, version: null };
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

/** Exact-version pins only; ranges and tags are not pins. */
export function isExactVersion(version) {
  if (typeof version !== "string") return false;
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version);
}

/** True when a string is an overly broad filesystem root (not a specific subfolder). */
export function isBroadRoot(value) {
  if (typeof value !== "string") return false;
  const v = value.trim().replace(/\\/g, "/");
  if (["/", ".", "..", "~", "//"].includes(v)) return true;

  // Windows drive roots: C:/ , C:/Users
  if (/^[A-Za-z]:\//.test(v)) {
    const segs = v.split("/").filter(Boolean).slice(1);
    return segs.length <= 1;
  }

  // POSIX absolute paths
  if (v.startsWith("/")) {
    const segs = v.split("/").filter(Boolean);
    if (segs.length === 0) return true;
    if (["home", "Users", "root", "mnt", "var", "etc", "tmp"].includes(segs[0])) {
      return segs.length <= 2; // /home or /home/user is broad; /home/user/project is not
    }
    return false;
  }

  // Home-relative paths
  if (v.startsWith("~/")) {
    return v.split("/").filter(Boolean).length <= 1;
  }
  return false;
}

const DANGEROUS_SHELL_RE = /(?:sh|bash|zsh|cmd(?:\.exe)?|powershell|pwsh)\s+(?:-c|\/c|-enc|-encodedcommand)\b|\beval\s*\(|\bexec\s*\(/i;

/** True when a command string delegates to a shell interpreter. */
export function isDangerousShell(value) {
  return typeof value === "string" && DANGEROUS_SHELL_RE.test(value);
}

export const DISABLE_FLAGS = [
  "--no-sandbox",
  "--disable-security",
  "--insecure",
  "--disable-web-security",
  "--no-verify",
  "--ignore-certificate-errors",
  "--allow-running-insecure-content"
];

/** Return any security-disabling flags present in a string. */
export function findDisableFlags(value) {
  if (typeof value !== "string") return [];
  const lower = value.toLowerCase();
  return DISABLE_FLAGS.filter((flag) => lower.includes(flag));
}

/** True when a URL is cleartext HTTP to a non-loopback host. */
export function isCleartextRemote(value) {
  if (typeof value !== "string" || !/^http:\/\//i.test(value)) return false;
  try {
    const host = new URL(value).hostname.toLowerCase();
    return !["localhost", "127.0.0.1", "::1", "[::1]"].includes(host);
  } catch {
    return true;
  }
}

/** Collect wildcard permission values from a config entry. */
export function findWildcardPermissions(entry) {
  const found = [];
  const keys = ["allowedTools", "allowed_tools", "tools", "capabilities", "permissions"];
  for (const key of keys) {
    const value = entry?.[key];
    if (value === "*" || (typeof value === "string" && value.toLowerCase() === "all")) {
      found.push({ field: key, value });
      continue;
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const item = value[i];
        if (item === "*" || (typeof item === "string" && item.toLowerCase() === "all")) {
          found.push({ field: `${key}[${i}]`, value: item });
        } else if (item && typeof item === "object" && Object.values(item).includes("*")) {
          found.push({ field: `${key}[${i}]`, value: JSON.stringify(item) });
        }
      }
    }
  }
  return found;
}

/** Approximate line/column for a value inside raw JSON text (1-based). */
export function locateInRaw(raw, value) {
  if (typeof raw !== "string" || typeof value !== "string" || !value) {
    return { startLine: 1, startColumn: 1 };
  }
  const idx = raw.indexOf(value);
  if (idx === -1) return { startLine: 1, startColumn: 1 };
  const before = raw.slice(0, idx);
  const lines = before.split(/\r?\n/);
  return { startLine: lines.length, startColumn: (lines[lines.length - 1] || "").length + 1 };
}
