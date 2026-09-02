import { ulid } from "ulid";
import { randomBytes } from "node:crypto";
import type { FindingRegistry, Probe } from "@perimeter/sdk";
import type { ScanConfig } from "./config/scan-config.js";
import { loadTargetModel } from "./target/loader.js";
import { IdentityManager } from "./identity/identity-manager.js";
import { FixtureManager } from "./identity/fixtures.js";
import { FindingRegistryImpl, type Baseline } from "./findings/registry.js";
import { RateLimiter } from "./safety/rate-limiter.js";
import { NdjsonAuditLog } from "./audit/audit-log.js";
import { GuardedHttpClientImpl } from "./http/guarded-http-client.js";
import { SafetyGuard } from "./safety/guard.js";
import { MutableBudget } from "./runtime/budget.js";
import { selectProbes } from "./engine/scheduler.js";
import { ExecutionEngine } from "./engine/execution-engine.js";
import { SystemClock } from "./runtime/clock.js";
import { ConsoleLogger } from "./runtime/logger.js";
import type { Clock, Logger } from "@perimeter/sdk";

/**
 * Scan orchestrator (spec §2.2). Wires the whole pipeline: load the Target Model,
 * enforce the authorization gate, select applicable probes, run them through the
 * execution engine, and hand back a finished FindingRegistry for the reporters.
 *
 * Every vulnerability class flows through this identical pipeline (spec §2.2).
 */
export interface OrchestratorOptions {
  clock?: Clock;
  logger?: Logger;
  baseline?: Baseline;
  signal?: AbortSignal;
}

export class Orchestrator {
  readonly #config: ScanConfig;
  readonly #probes: Probe[];
  readonly #opts: OrchestratorOptions;

  constructor(config: ScanConfig, probes: Probe[], opts: OrchestratorOptions = {}) {
    this.#config = config;
    this.#probes = probes;
    this.#opts = opts;
  }

  async run(): Promise<FindingRegistry> {
    const logger = this.#opts.logger ?? new ConsoleLogger("info");
    const clock = this.#opts.clock ?? new SystemClock();
    const scanId = ulid();
    const seed = this.#config.seed ?? randomBytes(8).toString("hex");
    const startedAt = new Date().toISOString();
    const timeoutSignal = AbortSignal.timeout(this.#config.maxWallClockSeconds * 1000);
    const signal = this.#opts.signal
      ? AbortSignal.any([this.#opts.signal, timeoutSignal])
      : timeoutSignal;

    const target = await loadTargetModel(this.#config.target);

    // §5.5 authorization gate — the engine refuses to run without an explicit
    // assertion, and production forces the most conservative rate profile.
    this.#assertAuthorized(target.authorization.environment, logger);

    const rateLimit = this.#effectiveRateLimit(target.authorization);
    const limiter = new RateLimiter(rateLimit, clock);
    const audit = new NdjsonAuditLog(this.#config.output.auditLog);
    const identities = new IdentityManager(target);
    const globalBudget = new MutableBudget(this.#config.maxTotalRequests);

    // FixtureManager needs a guarded client for setup. This client is the engine's
    // sanctioned write path (spec §4.3): it may POST to declared `creates:` factory
    // endpoints and DELETE the scratch objects it created — independent of the
    // probe-level --allow-mutating flag, which governs *probe* writes. The live
    // scratch-id set is shared with the setup guard and the per-probe guards, so
    // objects created here are recognized by every guard for the rest of the scan.
    const scratchIds = new Set<string>();
    const setupHttp = new GuardedHttpClientImpl({
      baseUrl: target.baseUrl,
      probeId: "engine/fixtures",
      probeSafetyClass: "idempotent-write",
      guard: new SafetyGuard({
        allowedHosts: new Set([new URL(target.baseUrl).host]),
        allowMutating: this.#config.allowMutating,
        scratchObjectIds: scratchIds,
        fixtureFactoryPaths: FixtureManager.factoryPaths(target),
        allowScratchWrites: true,
      }),
      limiter,
      budget: globalBudget,
      audit,
      scanId,
      resolveIdentity: (ref) => identities.get(ref),
      signal,
    });
    const fixtures = new FixtureManager(target, setupHttp, { logger, ids: scratchIds });
    const registry = new FindingRegistryImpl(this.#opts.baseline);

    const selection = selectProbes(this.#probes, target, {
      include: this.#config.include,
      exclude: this.#config.exclude,
    });
    for (const s of selection.skipped) registry.recordSkip(s.probeId, s.reason);
    logger.info("probes selected", {
      applicable: selection.applicable.length,
      skipped: selection.skipped.length,
    });

    const engine = new ExecutionEngine({
      target,
      scanId,
      seed,
      logger,
      clock,
      audit,
      identities,
      fixtures,
      registry,
      limiter,
      globalBudget,
      concurrency: this.#config.concurrency,
      allowMutating: this.#config.allowMutating,
      signal,
    });

    try {
      await engine.run(selection.applicable);
    } finally {
      await fixtures.teardownAll();
    }
    signal.throwIfAborted();

    const finishedAt = new Date().toISOString();
    return registry.export({
      scanId,
      target: target.name,
      seed,
      startedAt,
      finishedAt,
    });
  }

  #assertAuthorized(environment: string, logger: Logger): void {
    // The Zod schema already guarantees iAmAuthorizedToTest === true; this is the
    // production-specific extra guard (spec §2.3, §5.5).
    if (environment === "production") {
      if (process.env.PERIMETER_CONFIRM_PRODUCTION !== "yes") {
        throw new Error(
          "target environment is 'production': set PERIMETER_CONFIRM_PRODUCTION=yes to proceed (spec §5.5)",
        );
      }
      logger.warn("running against PRODUCTION — most conservative rate profile forced");
    }
  }

  #effectiveRateLimit(authz: import("@perimeter/sdk").Authorization) {
    if (authz.environment === "production") {
      // Force the most conservative profile regardless of what's configured.
      return { globalRps: 1, perHostRps: 1, burst: 1 };
    }
    return authz.rateLimit;
  }
}
