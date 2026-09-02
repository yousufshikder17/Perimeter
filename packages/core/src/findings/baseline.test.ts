import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { FindingRegistry } from "@perimeter/sdk";
import { createBaselineFile, loadBaseline } from "./baseline.js";

let directory: string | undefined;

afterEach(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

describe("finding baselines", () => {
  it("creates a deterministic, versioned set of accepted fingerprints", () => {
    const baseline = createBaselineFile(
      {
        target: "staging",
        findings: [{ fingerprint: "z" }, { fingerprint: "a" }, { fingerprint: "z" }],
      } as Pick<FindingRegistry, "target" | "findings">,
      "2026-09-02T12:00:00.000Z",
    );

    expect(baseline).toEqual({
      schemaVersion: "1.0",
      target: "staging",
      createdAt: "2026-09-02T12:00:00.000Z",
      acceptedFingerprints: ["a", "z"],
    });
  });

  it("loads valid files and rejects malformed baselines", async () => {
    directory = await mkdtemp(join(tmpdir(), "perimeter-baseline-"));
    const valid = join(directory, "valid.json");
    const invalid = join(directory, "invalid.json");
    await writeFile(
      valid,
      JSON.stringify({
        schemaVersion: "1.0",
        target: "staging",
        createdAt: "2026-09-02T12:00:00.000Z",
        acceptedFingerprints: ["known-finding"],
      }),
    );
    await writeFile(invalid, JSON.stringify({ acceptedFingerprints: [] }));

    await expect(loadBaseline(valid)).resolves.toMatchObject({
      acceptedFingerprints: new Set(["known-finding"]),
    });
    await expect(loadBaseline(invalid)).rejects.toThrow();
  });
});
