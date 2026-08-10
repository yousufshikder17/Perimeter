import {
  EvidenceSchema,
  type Finding,
  type Pass,
  type FindingRegistry,
  type Report,
  FINDING_SCHEMA_VERSION,
} from "@perimeter/sdk";

/**
 * Finding registry (spec §2.2 step 4, §6). Collects reports from probes,
 * enforces the evidence-on-finding rule at intake, applies a baseline of
 * accepted findings, and produces the machine-contract JSON export.
 */

export interface Baseline {
  /** Fingerprints marked accepted/known — suppressed from the gate (spec §8.6). */
  acceptedFingerprints: Set<string>;
}

export class FindingRegistryImpl {
  readonly #findings: Finding[] = [];
  readonly #passes: Pass[] = [];
  readonly #skipped: Array<{ probeId: string; reason: string }> = [];
  readonly #baseline: Baseline | undefined;

  constructor(baseline?: Baseline) {
    this.#baseline = baseline;
  }

  /** Intake from `ctx.report()`. Rejects a Finding without valid Evidence. */
  report(r: Report): void {
    if (isPass(r)) {
      this.#passes.push(r);
      return;
    }
    // Evidence is mandatory — no evidence, no finding (spec §3.2 rule 3, §6.2).
    const parsed = EvidenceSchema.safeParse(r.evidence);
    if (!parsed.success) {
      throw new Error(
        `finding "${r.probeId}" rejected: missing/invalid evidence bundle (spec §6.2): ${parsed.error.message}`,
      );
    }
    const status =
      this.#baseline?.acceptedFingerprints.has(r.fingerprint) ? "accepted" : r.status;
    this.#findings.push({ ...r, status });
  }

  recordSkip(probeId: string, reason: string): void {
    this.#skipped.push({ probeId, reason });
  }

  findings(): readonly Finding[] {
    return this.#findings;
  }
  passes(): readonly Pass[] {
    return this.#passes;
  }

  /** Highest severity among non-accepted/non-suppressed findings — drives the gate. */
  gatingSeverity(): Finding["severity"] | null {
    const order: Finding["severity"][] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    for (const sev of order) {
      if (this.#findings.some((f) => f.severity === sev && f.status === "open")) return sev;
    }
    return null;
  }

  export(meta: {
    scanId: string;
    target: string;
    seed: string;
    startedAt: string;
    finishedAt: string;
  }): FindingRegistry {
    return {
      schemaVersion: FINDING_SCHEMA_VERSION,
      ...meta,
      findings: this.#findings,
      passes: this.#passes,
      skipped: this.#skipped,
    };
  }
}

function isPass(r: Report): r is Pass {
  return (r as Pass).kind === "pass";
}
