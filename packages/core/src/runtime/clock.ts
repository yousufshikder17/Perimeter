import { setTimeout as sleepAsync } from "node:timers/promises";
import type { Clock } from "@perimeter/sdk";

/** Real wall-clock, used in local/CI profiles. */
export class SystemClock implements Clock {
  now(): number {
    return Date.now();
  }
  async sleep(ms: number, signal?: AbortSignal): Promise<void> {
    await sleepAsync(ms, undefined, { signal });
  }
}

/**
 * Virtual clock for deterministic tests — rate-limit probes and the limiter use
 * an injectable clock so time-based logic is reproducible (spec §3.2 rule 4).
 */
export class VirtualClock implements Clock {
  #nowMs: number;
  readonly #pending: Array<{ at: number; resolve: () => void }> = [];

  constructor(startMs = 0) {
    this.#nowMs = startMs;
  }

  now(): number {
    return this.#nowMs;
  }

  async sleep(ms: number, signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    return new Promise((resolve) => {
      this.#pending.push({ at: this.#nowMs + ms, resolve });
    });
  }

  /** Advance virtual time, releasing any sleeps whose deadline has passed. */
  advance(ms: number): void {
    this.#nowMs += ms;
    for (let i = this.#pending.length - 1; i >= 0; i--) {
      if (this.#pending[i]!.at <= this.#nowMs) {
        this.#pending[i]!.resolve();
        this.#pending.splice(i, 1);
      }
    }
  }
}
