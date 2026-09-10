import { ulid } from "ulid";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import type { FindingRegistry, Probe, TargetModel } from "@perimeter/sdk";
import type { ScanConfig } from "./config/scan-config.js";
import { loadTargetModel } from "./target/loader.js";
import { IdentityManager } from "./identity/identity-manager.js";
import { loadAuthHook } from "./identity/auth-hook.js";
import { createTokenExchange } from "./identity/token-exchange.js";
import { FixtureManager } from "./identity/fixtures.js";
import { FindingRegistryImpl, type Baseline } from "./findings/registry.js";
import { RateLimiter } from "./safety/rate-limiter.js";
import { NdjsonAuditLog } from "./audit/audit-log.js";
import { GuardedHttpClientImpl } from "./http/guarded-http-client.js";
import { SafetyGuard } from "./safety/guard.js";
import { MutableBudget } from "./runtime/budget.js";
import { selectProbes, type Selection } from "./engine/scheduler.js";
import { ScanCheckpoint } from "./runtime/checkpoint.js";
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
  maxResponseBytes?: number;
  captureBodies?: boolean;
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
    const target = await loadTargetModel(this.#config.target);
    this.#assertAuthorized(target.authorization.environment, this.#opts.logger ?? new ConsoleLogger("info"));
    const selection = selectProbes(this.#probes, target, this.#config);
    if (!this.#config.allowMutating) {
      selection.applicable = selection.applicable.filter((probe) => {
        if (probe.manifest.safety.class === "read-only" && !probe.manifest.safety.destructive) return true;
        selection.skipped.push({ probeId: probe.manifest.id, reason: "write probe requires --allow-mutating" });
        return false;
      });
    }
    let checkpoint: ScanCheckpoint | undefined;
    if (this.#config.checkpoint) {
      if (selection.applicable.some((p) => p.manifest.safety.class !== "read-only" || p.manifest.safety.destructive)) {
        throw new Error("Checkpoint replay supports only read-only probes");
      }
      if (new Set(this.#probes.map((p) => p.manifest.id)).size !== this.#probes.length) {
        throw new Error("Checkpoint scans require unique probe IDs");
      }
      const checkpointPath = resolve(this.#config.checkpoint);
      const protectedPaths = [this.#config.target, this.#config.baseline, ...Object.values(this.#config.output)]
        .filter((path): path is string => !!path).map((path) => resolve(path));
      if (protectedPaths.some((path) => path === checkpointPath || path === `${checkpointPath}.lock`)) {
        throw new Error("Checkpoint and lock paths must be separate from targets, baselines, and outputs");
      }
      const config = { ...this.#config, resume: false, checkpoint: undefined };
      checkpoint = await ScanCheckpoint.open(checkpointPath, this.#config.resume, {
        target, config, manifests: this.#probes.map((p) => p.manifest),
        baseline: [...this.#opts.baseline?.acceptedFingerprints ?? []].sort(),
        maxResponseBytes: this.#opts.maxResponseBytes, captureBodies: this.#opts.captureBodies,
      }, { scanId: ulid(), seed: this.#config.seed ?? randomBytes(8).toString("hex"), startedAt: new Date().toISOString() });
    }
    try {
      return await this.#execute(target, selection, checkpoint);
    } finally {
      await checkpoint?.release();
    }
  }

  async #execute(target: TargetModel, selection: Selection, checkpoint?: ScanCheckpoint): Promise<FindingRegistry> {
    const logger = this.#opts.logger ?? new ConsoleLogger("info");
    const clock = this.#opts.clock ?? new SystemClock();
    const scanId = checkpoint?.state.scanId ?? ulid();
    const seed = checkpoint?.state.seed ?? this.#config.seed ?? randomBytes(8).toString("hex");
    const startedAt = checkpoint?.state.startedAt ?? new Date().toISOString();
    const timeoutSignal = AbortSignal.timeout(this.#config.maxWallClockSeconds * 1000);
    const signal = this.#opts.signal
      ? AbortSignal.any([this.#opts.signal, timeoutSignal])
      : timeoutSignal;

    const customHook = await loadAuthHook(target, this.#config.target);
    signal.throwIfAborted();

    const rateLimit = this.#effectiveRateLimit(target.authorization);
    const limiter = new RateLimiter(rateLimit, clock);
    const audit = new NdjsonAuditLog(this.#config.output.auditLog, checkpoint?.state.used ?? 0);
    const globalBudget = new MutableBudget(this.#config.maxTotalRequests, undefined, checkpoint
      ? { used: checkpoint.state.used, save: (used) => checkpoint.reserve(used) } : undefined);
    const authenticationUrls = new Set([target.auth.tokenEndpoint, target.auth.refresh?.endpoint]
      .filter((url): url is string => !!url).map((url) => new URL(url, target.baseUrl).href));
    const authHttp = new GuardedHttpClientImpl({
      baseUrl: target.baseUrl, probeId: "engine/authentication", probeSafetyClass: "idempotent-write",
      guard: new SafetyGuard({ allowedHosts: new Set([new URL(target.baseUrl).host]),
        allowMutating: false, scratchObjectIds: new Set(), authenticationUrls }),
      limiter, budget: globalBudget, audit, scanId, signal, captureBodies: false,
      ...(this.#opts.maxResponseBytes !== undefined ? { maxResponseBytes: this.#opts.maxResponseBytes } : {}),
      resolveIdentity: () => { throw new Error("Authentication requests cannot recursively resolve an identity"); },
    });
    const identities = new IdentityManager(target, customHook, signal, createTokenExchange(target, authHttp));

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
        isScratchWrite: (method, url, id): boolean => fixtures.permitsWrite(method, url, id),
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

    const completed = new Set(checkpoint?.state.completed.map((r) => r.probeId));
    for (const result of checkpoint?.state.completed ?? []) {
      for (const report of [...result.findings, ...result.passes]) registry.report(report);
      for (const skip of result.skipped) registry.recordSkip(skip.probeId, skip.reason);
    }
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
      ...(checkpoint ? { onCompleted: (probeId: string) => checkpoint.complete(probeId,
        registry.export({ scanId, target: target.name, seed, startedAt, finishedAt: new Date().toISOString() })) } : {}),
      ...(this.#opts.maxResponseBytes !== undefined ? { maxResponseBytes: this.#opts.maxResponseBytes } : {}),
      ...(this.#opts.captureBodies !== undefined ? { captureBodies: this.#opts.captureBodies } : {}),
    });

    try {
      await engine.run(selection.applicable.filter((p) => !completed.has(p.manifest.id)));
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
