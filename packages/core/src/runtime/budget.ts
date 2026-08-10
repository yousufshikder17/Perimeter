import type { RequestBudget } from "@perimeter/sdk";

/**
 * Per-probe request budget (spec §3.2 rule 5, §4.1). The engine enforces the
 * ceiling from the manifest's `safety.maxRequests`; probes read `available()`
 * and stop cooperatively when exhausted.
 */
export class MutableBudget implements RequestBudget {
  readonly limit: number;
  #used = 0;

  constructor(limit: number) {
    this.limit = limit;
  }

  get used(): number {
    return this.#used;
  }
  get remaining(): number {
    return Math.max(0, this.limit - this.#used);
  }
  available(): boolean {
    return this.remaining > 0;
  }

  /** Called by the guarded client before each request; throws when exhausted. */
  consume(): void {
    if (!this.available()) {
      throw new Error(
        `per-probe request budget exhausted (${this.limit} requests, spec §4.1)`,
      );
    }
    this.#used += 1;
  }
}
