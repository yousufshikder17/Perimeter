/**
 * Secret redaction (spec §4.1: "Secrets are redacted on write"). Applied to
 * headers/bodies before anything is persisted to the audit log or an evidence
 * bundle. Redaction is best-effort defense-in-depth; the real guarantee is that
 * evidence never leaves the operator's machine (spec §4.2 exfiltration control).
 */

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
]);

/** Bounded body capture size (spec §4.1: bodies are size-bounded). */
export const MAX_CAPTURED_BODY_BYTES = 16 * 1024;

export function redactHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? "«redacted»" : v;
  }
  return out;
}

/** JWT-ish and bearer-token patterns scrubbed from free-text bodies. */
const TOKEN_PATTERNS: RegExp[] = [
  /Bearer\s+[A-Za-z0-9._-]+/gi,
  /eyJ[A-Za-z0-9._-]{10,}/g, // JWT
  /"(password|token|secret|api[_-]?key)"\s*:\s*"[^"]*"/gi,
];

export function redactBody(body: string | undefined): string | undefined {
  if (body === undefined) return undefined;
  let out = body.length > MAX_CAPTURED_BODY_BYTES
    ? `${body.slice(0, MAX_CAPTURED_BODY_BYTES)}…«truncated»`
    : body;
  for (const re of TOKEN_PATTERNS) {
    out = out.replace(re, (m) => (m.includes(":") ? m.replace(/:.*/, ': "«redacted»"') : "«redacted»"));
  }
  return out;
}
