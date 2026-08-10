/**
 * Outbound payload inspector (spec §4.1, §4.2).
 *
 * Even injection probes must never emit destructive SQL verbs or stacked writes.
 * The inspector validates request bodies/queries *before* they leave the engine
 * — an engine-level invariant, not probe etiquette. A misbehaving probe cannot
 * escape it because it has no path to the network except the guarded client.
 */

/** Destructive/stacked-write SQL verbs that must never appear in outbound payloads. */
const DESTRUCTIVE_SQL =
  /\b(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT|GRANT|REVOKE|CREATE\s+(TABLE|DATABASE|USER))\b/i;

/** Stacked-statement injection attempt (`; <verb>`). */
const STACKED_STATEMENT = /;\s*(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT|SHUTDOWN)/i;

export interface InspectionResult {
  ok: boolean;
  reason?: string;
}

export function inspectOutboundPayload(
  parts: Array<string | undefined>,
): InspectionResult {
  for (const part of parts) {
    if (!part) continue;
    if (STACKED_STATEMENT.test(part)) {
      return { ok: false, reason: "stacked SQL statement detected in payload" };
    }
    if (DESTRUCTIVE_SQL.test(part)) {
      return {
        ok: false,
        reason: "destructive SQL verb detected in payload (no-destructive-verb rule, spec §4.2)",
      };
    }
  }
  return { ok: true };
}

/** Idempotent HTTP methods permitted under the read-only default (spec §3.2 rule 2). */
const READ_ONLY_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function isReadOnlyMethod(method: string): boolean {
  return READ_ONLY_METHODS.has(method.toUpperCase());
}
