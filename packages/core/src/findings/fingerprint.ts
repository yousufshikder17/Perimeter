import { createHash } from "node:crypto";

/**
 * Stable finding fingerprint (spec §6.1, §6.2) = hash(probeId + endpoint + class
 * + locator). Deterministic so CI can baseline, suppress accepted findings, and
 * detect regressions across runs. Deliberately excludes volatile fields (ULID
 * id, timestamps, seed) so the same defect fingerprints identically each scan.
 */
export function computeFingerprint(input: {
  probeId: string;
  endpointId: string;
  family: string;
  /** A within-endpoint locator: object ref, field name, param, etc. */
  locator: string;
}): string {
  const canonical = [input.probeId, input.endpointId, input.family, input.locator].join("|");
  return "fp_" + createHash("sha256").update(canonical).digest("hex").slice(0, 32);
}
