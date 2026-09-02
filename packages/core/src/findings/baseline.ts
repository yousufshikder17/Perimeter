import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { FindingRegistry } from "@perimeter/sdk";
import type { Baseline } from "./registry.js";

export const BASELINE_SCHEMA_VERSION = "1.0" as const;

export const BaselineFileSchema = z
  .object({
    schemaVersion: z.literal(BASELINE_SCHEMA_VERSION),
    target: z.string().min(1),
    createdAt: z.string().datetime({ offset: true }),
    acceptedFingerprints: z.array(z.string().min(1)).default([]),
  })
  .strict();

export type BaselineFile = z.infer<typeof BaselineFileSchema>;

export function createBaselineFile(
  registry: Pick<FindingRegistry, "target" | "findings">,
  createdAt = new Date().toISOString(),
): BaselineFile {
  return BaselineFileSchema.parse({
    schemaVersion: BASELINE_SCHEMA_VERSION,
    target: registry.target,
    createdAt,
    acceptedFingerprints: [
      ...new Set(registry.findings.map((finding) => finding.fingerprint)),
    ].sort(),
  });
}

export async function loadBaseline(path: string): Promise<Baseline> {
  const parsed = BaselineFileSchema.parse(JSON.parse(await readFile(path, "utf8")));
  return { acceptedFingerprints: new Set(parsed.acceptedFingerprints) };
}
