import { describe, it, expect } from "vitest";
import { RateLimiter, VirtualClock } from "@perimeter/core";

/**
 * The engine cannot exceed the configured rate caps (spec §8.9). Uses the
 * virtual clock so the invariant is deterministic and instant.
 */
describe("global rate governance (spec §4.1)", () => {
  it("smooths a burst to the configured rate", async () => {
    const clock = new VirtualClock();
    const limiter = new RateLimiter({ globalRps: 5, perHostRps: 5, burst: 2 }, clock);

    // First `burst` acquisitions succeed immediately.
    await limiter.acquire("h");
    await limiter.acquire("h");

    // The next one must wait — kick it off, then advance virtual time to release.
    let released = false;
    const pending = limiter.acquire("h").then(() => (released = true));
    // Not yet: no time has passed.
    await Promise.resolve();
    expect(released).toBe(false);

    // Advance ~200ms (1 token at 5 rps) and let the loop re-check.
    for (let i = 0; i < 5 && !released; i++) {
      clock.advance(200);
      await Promise.resolve();
      await Promise.resolve();
    }
    await pending;
    expect(released).toBe(true);
  });

  it("honors an abort signal while waiting", async () => {
    const clock = new VirtualClock();
    const limiter = new RateLimiter({ globalRps: 1, perHostRps: 1, burst: 1 }, clock);
    const ac = new AbortController();
    await limiter.acquire("h"); // consume the only token
    ac.abort();
    await expect(limiter.acquire("h", ac.signal)).rejects.toThrow();
  });
});
