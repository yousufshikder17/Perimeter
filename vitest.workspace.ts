import { defineWorkspace } from "vitest/config";

/**
 * Two test projects:
 *  - unit:   unit + fixture tests across packages (`pnpm test`).
 *  - safety: the engine safety-invariant suite (`pnpm test:safety`), the gated
 *    invariants from spec §8.9 — a named project so it can be run in isolation
 *    and can never be silently skipped.
 */
export default defineWorkspace([
  {
    test: {
      name: "unit",
      include: ["packages/**/src/**/*.test.ts"],
      environment: "node",
    },
  },
  {
    test: {
      name: "safety",
      include: ["tests/safety/**/*.test.ts"],
      environment: "node",
    },
  },
  {
    test: {
      name: "e2e",
      include: ["tests/e2e/**/*.test.ts"],
      environment: "node",
      // Boots the reference target and runs a full rate-limited scan; give it room.
      testTimeout: 30000,
      hookTimeout: 30000,
    },
  },
]);
