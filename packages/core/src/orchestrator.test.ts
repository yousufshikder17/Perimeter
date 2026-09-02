import { describe, expect, it } from "vitest";
import type { Probe } from "@perimeter/sdk";
import { parseScanConfig } from "./config/scan-config.js";
import { Orchestrator } from "./orchestrator.js";

describe("scan wall-clock limit", () => {
  it("aborts and fails a scan that exceeds its configured limit", async () => {
    const probe: Probe = {
      manifest: {
        id: "test/timeout",
        family: "test",
        version: "1.0.0",
        schemaVersion: "1.0.0",
        requires: {},
        safety: { class: "read-only", maxRequests: 1, destructive: false },
      },
      async plan() {
        return { probeId: "test/timeout", steps: [] };
      },
      async run(_plan, context) {
        await context.clock.sleep(60_000, context.signal);
      },
    };
    const config = parseScanConfig({
      target: "examples/target.yaml",
      maxWallClockSeconds: 1,
      output: { auditLog: "audit.ndjson" },
    });

    await expect(new Orchestrator(config, [probe]).run()).rejects.toMatchObject({
      name: "TimeoutError",
    });
  });
});
