import type { TargetModel, IdentityRef } from "./target-model.js";
import type { Finding, Pass, HttpExchange } from "./finding.js";

/**
 * The runtime surface a probe is allowed to touch (spec §3.2).
 *
 * ProbeContext is the ONLY way a probe reaches the outside world. There is no
 * `fetch`, no `node:http`, no clock, no `Math.random` in a well-behaved probe —
 * everything flows through here so the engine can enforce the safety envelope
 * (spec §4.2). A probe that imports raw network APIs fails the linter (spec §3.4).
 */

// ---------------------------------------------------------------------------
// Guarded HTTP client — the ONLY network egress (spec §3.2 rule 1)
// ---------------------------------------------------------------------------

export interface GuardedRequest {
  method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
  /** Path or absolute URL; the guard rejects anything off the modeled host(s). */
  url: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  /** Issue this request authenticated as the given identity (engine mints creds). */
  as?: IdentityRef;
  /**
   * The scratch object id this request writes to, if any. The safety guard permits
   * a write only when it targets a probe-created scratch object (spec §4.2); this
   * is how the caller declares that target. Ignored for read-only methods.
   */
  targetsScratchObjectId?: string;
}

export interface GuardedResponse {
  /** Uncombined Set-Cookie fields, for engine-owned session authentication. */
  setCookies?: string[];
  status: number;
  headers: Record<string, string>;
  /** Size-bounded, secret-redacted body (spec §4.1). */
  text(): Promise<string>;
  json<T = unknown>(): Promise<T>;
  elapsedMs: number;
  /** The recorded, sanitized exchange — attach to a Finding's evidence. */
  readonly exchange: HttpExchange;
}

/**
 * Every call is rate-limited (global + per-host), counted against the per-probe
 * budget, host-allow-listed, method/verb-policed, and appended to the audit log.
 * Non-idempotent methods are refused unless the manifest safety class permits AND
 * the scan authorizes it, and even then must target probe-created scratch objects.
 */
export interface GuardedHttpClient {
  request(req: GuardedRequest): Promise<GuardedResponse>;
  get(url: string, init?: Omit<GuardedRequest, "method" | "url">): Promise<GuardedResponse>;
}

// ---------------------------------------------------------------------------
// Identity handles (minted by the engine — spec §4.3)
// ---------------------------------------------------------------------------

export interface Identity {
  readonly ref: IdentityRef;
  readonly tenant: string;
  readonly role: string;
  /** Auth headers to attach; refreshed by the engine on expiry. */
  headers(): Promise<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Scratch fixtures (provisioned by the engine — spec §4.3)
// ---------------------------------------------------------------------------

/**
 * A disposable object the engine created (via a `creates:` factory endpoint) so
 * probes test against known, non-real data rather than poking real records. The
 * engine tracks it and tears it down at scan end.
 */
export interface ScratchFixture {
  readonly id: string;
  readonly kind: string;
  readonly ownerTenant: string;
  readonly ownerIdentity: IdentityRef;
}

/**
 * Read-only view of the scratch fixtures the engine provisioned for this scan.
 * A probe that needs "an object owned by tenant B" asks here instead of
 * fabricating an id — the engine already created it as tenant B (spec §4.3).
 */
export interface FixtureView {
  /** The scratch object of `kind` owned by `ownerIdentity`, or undefined if none was provisioned. */
  owned(kind: string, ownerIdentity: IdentityRef): ScratchFixture | undefined;
  /** All provisioned scratch objects of `kind`, in creation order. */
  ofKind(kind: string): readonly ScratchFixture[];
}

// ---------------------------------------------------------------------------
// Determinism & control primitives (spec §3.2 rules 4 & 5)
// ---------------------------------------------------------------------------

/** Deterministic RNG seeded from the scan config — all probe randomness flows here. */
export interface SeededRng {
  /** Float in [0, 1). */
  next(): number;
  int(minInclusive: number, maxExclusive: number): number;
  pick<T>(items: readonly T[]): T;
  /** A fresh, independently-seeded sub-stream (e.g. per endpoint). */
  fork(label: string): SeededRng;
}

/** Injectable clock — probes must NOT read wall-clock for control flow (spec §3.2). */
export interface Clock {
  now(): number; // epoch ms
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
}

/** Remaining per-probe request budget; probes stop when exhausted (spec §3.2 rule 5). */
export interface RequestBudget {
  readonly limit: number;
  readonly used: number;
  readonly remaining: number;
  /** True while there is budget left; probes should check before each request. */
  available(): boolean;
}

export interface Logger {
  debug(msg: string, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
  child(bindings: Record<string, unknown>): Logger;
}

// ---------------------------------------------------------------------------
// ProbeContext (spec §3.2)
// ---------------------------------------------------------------------------

export interface ProbeContext {
  /** Read-only view of the Target Model (spec §5). */
  readonly target: TargetModel;
  /** The ONLY network egress (spec §3.2 rule 1). */
  readonly http: GuardedHttpClient;
  /** Scratch objects the engine provisioned for this scan (spec §4.3). */
  readonly fixtures: FixtureView;
  /** Mint/fetch credentials for a tenant/role. */
  identity(ref: IdentityRef): Identity;
  /**
   * Structured output (spec §6). `report()` REJECTS a Finding without an attached
   * Evidence bundle at runtime — no evidence, no finding (spec §3.2 rule 3).
   */
  report(f: Finding | Pass): void;
  readonly logger: Logger;
  readonly rng: SeededRng;
  readonly clock: Clock;
  readonly signal: AbortSignal; // cooperative cancellation
  readonly budget: RequestBudget;
}
