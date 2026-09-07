import type { SafetyClass } from "@perimeter/sdk";
import { inspectOutboundPayload, isReadOnlyMethod } from "./outbound-inspector.js";

/**
 * Safety guard — THE choke point (spec §4.1 responsibility 3, §4.2).
 *
 * Every request passes through here and is checked for:
 *   - target-host allow-list (only the modeled target),
 *   - method policy (read-only unless the probe's safety class + scan authorize),
 *   - payload policy (no destructive SQL verbs, validated by the inspector),
 *   - the scratch-object rule for any permitted write.
 *
 * These are engine-level invariants. A malicious probe cannot escape them
 * because the guarded client is its only network path.
 */

export interface GuardPolicy {
  /** Exact POST URLs for the engine-owned authentication client only. */
  authenticationUrls?: ReadonlySet<string>;
  /** Hosts egress is allowed to reach — the modeled target only (spec §4.2). */
  allowedHosts: ReadonlySet<string>;
  /** Whether the scan authorized writes (requires --allow-mutating + authz opt-in). */
  allowMutating: boolean;
  /** Ids of engine-created scratch objects that writes may target (spec §4.3). */
  scratchObjectIds: ReadonlySet<string>;
  /**
   * Pathnames the engine may POST to in order to CREATE scratch fixtures — the
   * `creates:` factory endpoints (spec §4.3, §5.3). Set ONLY on the engine's
   * fixture-setup client, never on a probe client, so probes cannot POST to a
   * factory. Empty/undefined ⇒ no factory writes permitted.
   */
  fixtureFactoryPaths?: ReadonlySet<string>;
  /**
   * If true (the fixture-setup client), writes targeting a tracked scratch object
   * are permitted without `--allow-mutating`: the engine owns those objects and
   * created them itself, so setup + teardown are the one sanctioned write path
   * (spec §4.3). Probe clients leave this false — their writes still require the
   * flag AND the scratch-object rule.
   */
  allowScratchWrites?: boolean;
}

export interface GuardCheckInput {
  method: string;
  url: string;
  probeSafetyClass: SafetyClass;
  /** Body + query string, for the outbound payload inspector. */
  payloadParts: Array<string | undefined>;
  /** Object id this write targets, if the probe declared one (write path only). */
  targetsScratchObjectId?: string;
}

export class SafetyViolation extends Error {
  constructor(reason: string) {
    super(`safety guard blocked request: ${reason}`);
    this.name = "SafetyViolation";
  }
}

export class SafetyGuard {
  readonly #policy: GuardPolicy;

  constructor(policy: GuardPolicy) {
    this.#policy = policy;
  }

  /** Throws SafetyViolation if the request is not permitted. Called on EVERY egress. */
  check(input: GuardCheckInput): void {
    this.#checkHost(input.url);
    this.#checkMethod(input);
    this.#checkPayload(input.payloadParts);
  }

  #checkHost(url: string): void {
    let host: string;
    try {
      host = new URL(url).host;
    } catch {
      throw new SafetyViolation(`malformed URL: ${url}`);
    }
    if (!this.#policy.allowedHosts.has(host)) {
      throw new SafetyViolation(
        `host "${host}" is not in the target allow-list — egress is on-target only (spec §4.2)`,
      );
    }
  }

  #checkMethod(input: GuardCheckInput): void {
    if (isReadOnlyMethod(input.method)) return;
    if (input.method === "POST" && this.#policy.authenticationUrls?.has(input.url)) return;

    // Sanctioned fixture CREATION: a POST to a declared `creates:` factory path,
    // issued by the engine's fixture-setup client (spec §4.3). The operator opted
    // in by annotating the endpoint `creates:` and asserting authorization; this
    // is the engine making disposable test data, not mutating existing records.
    if (input.method === "POST" && this.#isFactoryPath(input.url)) return;

    const targetsTrackedScratch =
      !!input.targetsScratchObjectId &&
      this.#policy.scratchObjectIds.has(input.targetsScratchObjectId);

    // Sanctioned fixture TEARDOWN / setup-owned scratch write: the setup client
    // may write to the scratch objects it created, without --allow-mutating.
    if (this.#policy.allowScratchWrites && targetsTrackedScratch) return;

    // Any other non-idempotent method: requires manifest permission AND scan
    // authorization, and even then must hit a probe-created scratch object.
    const writeAllowedByClass =
      input.probeSafetyClass === "idempotent-write" ||
      input.probeSafetyClass === "mutating";

    if (!writeAllowedByClass || !this.#policy.allowMutating) {
      throw new SafetyViolation(
        `method ${input.method} refused: read-only by default; requires safety.class write + --allow-mutating (spec §3.2 rule 2)`,
      );
    }
    if (!targetsTrackedScratch) {
      throw new SafetyViolation(
        `write must target a probe-created scratch object, not pre-existing data (spec §4.2)`,
      );
    }
  }

  #isFactoryPath(url: string): boolean {
    const paths = this.#policy.fixtureFactoryPaths;
    if (!paths || paths.size === 0) return false;
    try {
      return paths.has(new URL(url).pathname);
    } catch {
      return false;
    }
  }

  #checkPayload(parts: Array<string | undefined>): void {
    const result = inspectOutboundPayload(parts);
    if (!result.ok) {
      throw new SafetyViolation(result.reason ?? "payload policy violation");
    }
  }
}
