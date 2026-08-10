import type { ProbeManifest } from "./manifest.js";
import type { ProbeContext } from "./context.js";

/**
 * The probe lifecycle contract (spec §3.2).
 *
 * Every probe — the five standard families and any third-party family — shares
 * this one contract. Authoring a probe requires understanding *the
 * vulnerability*, not the engine internals.
 */

/** A concrete step a probe intends to run, produced during `plan()`. */
export interface ProbeStep {
  /** Stable id within the plan, for audit correlation. */
  id: string;
  description: string;
  /** The endpoint (by Target Model id) this step exercises, if any. */
  endpointId?: string;
  /** Estimated request cost — must fit within the manifest's `safety.maxRequests`. */
  estimatedRequests: number;
}

export interface ProbePlan {
  readonly probeId: string;
  readonly steps: ProbeStep[];
}

/** Returned from `plan()` when a probe does not apply — always with a reason (spec §2.2). */
export interface Skip {
  readonly skip: true;
  readonly reason: string;
}

export function skip(reason: string): Skip {
  return { skip: true, reason };
}

export function isSkip(x: ProbePlan | Skip): x is Skip {
  return (x as Skip).skip === true;
}

export interface Probe {
  /** Static identity & requirements; pure, no side effects (spec §3.2). */
  readonly manifest: ProbeManifest;

  /**
   * Decide whether this probe applies to the modeled target. Returns a plan (the
   * concrete steps it intends to run) or a skip reason.
   *
   * MUST NOT issue any network request here.
   */
  plan(ctx: ProbeContext): Promise<ProbePlan | Skip>;

  /**
   * Execute the planned steps. All outbound traffic goes through `ctx.http`
   * (rate-limited, audited, safety-checked). Emit findings or passes via
   * `ctx.report()`.
   *
   * MUST be safe to abort at any `await` point (honor `ctx.signal`).
   */
  run(plan: ProbePlan, ctx: ProbeContext): Promise<void>;
}

/**
 * A probe family export: probes distributed as npm packages expose a
 * `perimeter.probes` array (spec §3.1). Local probes live under `probes/`.
 */
export interface ProbePackage {
  readonly perimeter: {
    readonly probes: Probe[];
  };
}
