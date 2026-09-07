import type { Probe, ProbeContext, IdentityRef } from "@perimeter/sdk";
import { isSkip } from "@perimeter/sdk";
import { SafetyGuard } from "../safety/guard.js";
import { RateLimiter } from "../safety/rate-limiter.js";
import { MutableBudget } from "../runtime/budget.js";
import { DeterministicRng } from "../runtime/rng.js";
import { GuardedHttpClientImpl } from "../http/guarded-http-client.js";
import type { AuditSink } from "../audit/audit-log.js";
import type { IdentityManager } from "../identity/identity-manager.js";
import { AuthenticationError } from "../identity/identity-manager.js";
import type { FixtureManager } from "../identity/fixtures.js";
import type { FindingRegistryImpl } from "../findings/registry.js";
import type { Logger, Clock, TargetModel } from "@perimeter/sdk";

/**
 * Execution engine (spec §4). Runs the applicable probes with bounded
 * concurrency, each behind its own budget + guarded client, all sharing the one
 * global rate limiter and audit log. This is where safe/audited/rate-limited/
 * never-destructive is made real and non-bypassable.
 */
export interface EngineDeps {
  target: TargetModel;
  scanId: string;
  seed: string;
  logger: Logger;
  clock: Clock;
  audit: AuditSink;
  identities: IdentityManager;
  fixtures: FixtureManager;
  registry: FindingRegistryImpl;
  limiter: RateLimiter;
  globalBudget: MutableBudget;
  concurrency: number;
  allowMutating: boolean;
  signal: AbortSignal;
  maxResponseBytes?: number;
  captureBodies?: boolean;
}

export class ExecutionEngine {
  readonly #d: EngineDeps;

  constructor(deps: EngineDeps) {
    this.#d = deps;
  }

  /** Execute all applicable probes, respecting the concurrency bound. */
  async run(probes: Probe[]): Promise<void> {
    // Provision scratch fixtures BEFORE any probe runs, so isolation/IDOR probes
    // reference engine-created, disposable objects instead of real records (§4.3).
    await this.#provisionFixtures(probes);

    const queue = [...probes];
    const workers = Array.from({ length: Math.min(this.#d.concurrency, queue.length || 1) }, () =>
      this.#worker(queue),
    );
    // Let in-flight siblings settle before teardown when authentication fails.
    const results = await Promise.allSettled(workers);
    for (const result of results) {
      if (result.status === "rejected") throw result.reason;
    }
  }

  /**
   * Create one scratch object per (creatable kind × required identity). "Required"
   * is the union of the applicable probes' `requires.identities`, intersected with
   * the modeled identities — so a scan only creates the fixtures its probes could
   * actually use. Per-object failures are logged and skipped, never fatal.
   */
  async #provisionFixtures(probes: Probe[]): Promise<void> {
    const kinds = [
      ...new Set(this.#d.target.endpoints.map((e) => e.creates).filter((k): k is string => !!k)),
    ];
    if (kinds.length === 0) return;

    const modeled = new Set(this.#d.target.identities.map((i) => i.ref));
    const needed = new Set<IdentityRef>();
    for (const probe of probes) {
      for (const ref of probe.manifest.requires.identities ?? []) {
        if (modeled.has(ref)) needed.add(ref);
      }
    }
    if (needed.size === 0) return;

    let created = 0;
    for (const kind of kinds) {
      for (const ref of needed) {
        if (this.#d.signal.aborted) return;
        try {
          await this.#d.fixtures.create(kind, ref);
          created++;
        } catch (err) {
          if (err instanceof AuthenticationError) throw err;
          this.#d.logger.warn("fixture provisioning failed (skipped)", {
            kind,
            identity: ref,
            error: String(err),
          });
        }
      }
    }
    this.#d.logger.info("fixtures provisioned", { created, kinds: kinds.length });
  }

  async #worker(queue: Probe[]): Promise<void> {
    for (;;) {
      if (this.#d.signal.aborted) return;
      const probe = queue.shift();
      if (!probe) return;
      await this.#runOne(probe);
    }
  }

  async #runOne(probe: Probe): Promise<void> {
    const log = this.#d.logger.child({ probe: probe.manifest.id });
    const ctx = this.#buildContext(probe);
    try {
      const plan = await probe.plan(ctx);
      if (isSkip(plan)) {
        this.#d.registry.recordSkip(probe.manifest.id, plan.reason);
        log.info("probe skipped", { reason: plan.reason });
        return;
      }
      log.info("probe running", { steps: plan.steps.length });
      await probe.run(plan, ctx);
    } catch (err) {
      if (err instanceof AuthenticationError) throw err;
      // A crashing/misbehaving probe cannot corrupt the scan or escape the guard.
      log.error("probe errored", { error: String(err) });
      this.#d.registry.recordSkip(probe.manifest.id, `errored: ${String(err)}`);
    }
  }

  #buildContext(probe: Probe): ProbeContext {
    const budget = new MutableBudget(probe.manifest.safety.maxRequests, this.#d.globalBudget);
    const guard = new SafetyGuard({
      allowedHosts: new Set([new URL(this.#d.target.baseUrl).host]),
      allowMutating: this.#d.allowMutating,
      scratchObjectIds: this.#d.fixtures.scratchObjectIds(),
    });
    const http = new GuardedHttpClientImpl({
      baseUrl: this.#d.target.baseUrl,
      probeId: probe.manifest.id,
      probeSafetyClass: probe.manifest.safety.class,
      guard,
      limiter: this.#d.limiter,
      budget,
      audit: this.#d.audit,
      scanId: this.#d.scanId,
      resolveIdentity: (ref: IdentityRef) => this.#d.identities.get(ref),
      signal: this.#d.signal,
      ...(this.#d.maxResponseBytes !== undefined ? { maxResponseBytes: this.#d.maxResponseBytes } : {}),
      ...(this.#d.captureBodies !== undefined ? { captureBodies: this.#d.captureBodies } : {}),
    });

    return {
      target: this.#d.target,
      http,
      fixtures: this.#d.fixtures.view(),
      budget,
      logger: this.#d.logger.child({ probe: probe.manifest.id }),
      rng: new DeterministicRng(`${this.#d.seed}::${probe.manifest.id}`),
      clock: this.#d.clock,
      signal: this.#d.signal,
      identity: (ref) => this.#d.identities.get(ref),
      report: (r) => this.#d.registry.report(r),
    };
  }
}
