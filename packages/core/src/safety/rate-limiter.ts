import type { Clock } from "@perimeter/sdk";

/**
 * Global + per-host token-bucket limiter (spec §4.1, §4.2).
 *
 * A single limiter sits in front of ALL egress, independent of any probe's own
 * budget. No probe can exceed it; bursts are smoothed. Deterministic and
 * testable via an injected clock — the limiter never reads wall-clock directly.
 */

export interface RateLimitConfig {
  globalRps: number;
  perHostRps: number;
  burst: number;
}

interface Bucket {
  tokens: number;
  lastRefillMs: number;
}

export class RateLimiter {
  readonly #config: RateLimitConfig;
  readonly #clock: Clock;
  readonly #global: Bucket;
  readonly #perHost = new Map<string, Bucket>();

  constructor(config: RateLimitConfig, clock: Clock) {
    this.#config = config;
    this.#clock = clock;
    this.#global = { tokens: config.burst, lastRefillMs: clock.now() };
  }

  /**
   * Block until one token is available from BOTH the global and the host bucket,
   * then consume from each. Honors cancellation via the optional signal.
   */
  async acquire(host: string, signal?: AbortSignal): Promise<void> {
    for (;;) {
      signal?.throwIfAborted();
      const waitMs = this.#tryConsume(host);
      if (waitMs === 0) return;
      await this.#clock.sleep(waitMs, signal);
    }
  }

  /** Returns 0 if a token was consumed, else ms to wait before the next attempt. */
  #tryConsume(host: string): number {
    const now = this.#clock.now();
    const hostBucket = this.#hostBucket(host, now);
    this.#refill(this.#global, this.#config.globalRps, now);
    this.#refill(hostBucket, this.#config.perHostRps, now);

    if (this.#global.tokens >= 1 && hostBucket.tokens >= 1) {
      this.#global.tokens -= 1;
      hostBucket.tokens -= 1;
      return 0;
    }
    // Wait for whichever bucket is more starved.
    const globalWait = this.#msUntilToken(this.#global, this.#config.globalRps);
    const hostWait = this.#msUntilToken(hostBucket, this.#config.perHostRps);
    return Math.max(globalWait, hostWait, 1);
  }

  #hostBucket(host: string, now: number): Bucket {
    let b = this.#perHost.get(host);
    if (!b) {
      b = { tokens: this.#config.burst, lastRefillMs: now };
      this.#perHost.set(host, b);
    }
    return b;
  }

  #refill(bucket: Bucket, rps: number, now: number): void {
    const elapsed = now - bucket.lastRefillMs;
    if (elapsed <= 0) return;
    bucket.tokens = Math.min(
      this.#config.burst,
      bucket.tokens + (elapsed / 1000) * rps,
    );
    bucket.lastRefillMs = now;
  }

  #msUntilToken(bucket: Bucket, rps: number): number {
    if (bucket.tokens >= 1) return 0;
    return Math.ceil(((1 - bucket.tokens) / rps) * 1000);
  }
}
