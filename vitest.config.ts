import { defineConfig } from "vitest/config";

/**
 * Root Vitest config. Test projects (unit + safety) are declared in
 * vitest.workspace.ts so the safety-invariant suite can be run in isolation via
 * `vitest run --project safety` (spec §8.9).
 */
export default defineConfig({
  test: {
    environment: "node",
  },
});
