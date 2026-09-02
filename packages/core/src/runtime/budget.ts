import type { RequestBudget } from "@perimeter/sdk";

/**
 * Request budget (spec §3.2 rule 5, §4.1). A per-probe budget may share a
 * scan-wide parent so both ceilings are enforced by the guarded client.
 */
export class MutableBudget implements RequestBudget {
  readonly limit: number;
  readonly #parent: MutableBudget | undefined;
  #used = 0;

  constructor(limit: number, parent?: MutableBudget) {
    this.limit = limit;
    this.#parent = parent;
  }

  get used(): number {
    return this.#used;
  }
  get remaining(): number {
    return Math.min(Math.max(0, this.limit - this.#used), this.#parent?.remaining ?? Infinity);
  }
  available(): boolean {
    return this.remaining > 0;
  }

  /** Called by the guarded client before each request; throws when exhausted. */
  consume(): void {
    if (this.limit - this.#used <= 0)
      throw new Error(`request budget exhausted (${this.limit} requests, spec §4.1)`);
    this.#parent?.consume();
    this.#used += 1;
  }
}
