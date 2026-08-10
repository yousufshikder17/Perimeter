import { ulid } from "ulid";
import type { Finding, Evidence, Remediation, Severity, Confidence, ProbeFamily } from "@perimeter/sdk";
import { computeFingerprint } from "@perimeter/core";

/**
 * Shared helper for constructing a schema-valid Finding with a stable
 * fingerprint (spec §6.1). Keeps every probe's finding shape consistent so the
 * registry, reporters, and baseline diffing behave identically across families.
 */
export function buildFinding(input: {
  probeId: string;
  family: ProbeFamily;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe?: string[];
  owaspApi?: string[];
  target: Finding["target"];
  affectedIdentities: string[];
  /** Within-endpoint locator for the fingerprint (field, param, object id, …). */
  locator: string;
  evidence: Evidence;
  remediation: Remediation;
}): Finding {
  const now = new Date().toISOString();
  return {
    id: ulid(),
    fingerprint: computeFingerprint({
      probeId: input.probeId,
      endpointId: input.target.endpointId,
      family: String(input.family),
      locator: input.locator,
    }),
    schemaVersion: "1.0",
    probeId: input.probeId,
    family: input.family,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence,
    ...(input.cwe ? { cwe: input.cwe } : {}),
    ...(input.owaspApi ? { owaspApi: input.owaspApi } : {}),
    target: input.target,
    affectedIdentities: input.affectedIdentities,
    evidence: input.evidence,
    remediation: input.remediation,
    firstSeen: now,
    lastSeen: now,
    status: "open",
  };
}
