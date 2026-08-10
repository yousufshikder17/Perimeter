import type { SeededRng } from "@perimeter/sdk";

/**
 * Deterministic RNG (spec §3.2 rule 4). All probe randomness flows through here
 * so a finding reproduces from the recorded seed. Uses splitmix64-derived
 * mulberry32 — small, fast, and identical across platforms.
 */

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Cheap string → 32-bit hash for deriving sub-stream seeds. */
function hashLabel(seed: string): number {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export class DeterministicRng implements SeededRng {
  readonly #seedLabel: string;
  readonly #next: () => number;

  constructor(seedLabel: string) {
    this.#seedLabel = seedLabel;
    this.#next = mulberry32(hashLabel(seedLabel));
  }

  next(): number {
    return this.#next();
  }

  int(minInclusive: number, maxExclusive: number): number {
    return minInclusive + Math.floor(this.next() * (maxExclusive - minInclusive));
  }

  pick<T>(items: readonly T[]): T {
    if (items.length === 0) throw new Error("cannot pick from an empty array");
    return items[this.int(0, items.length)]!;
  }

  fork(label: string): SeededRng {
    return new DeterministicRng(`${this.#seedLabel}::${label}`);
  }
}
