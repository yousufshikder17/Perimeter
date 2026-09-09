import { z } from "zod";
import { IsolatedProbeSchema } from "../isolation/protocol.js";

/**
 * Scan configuration (spec §4.1 responsibility 5, §8). A scan has a seed and a
 * resolved-probe manifest; re-running the same seed against the same target
 * version reproduces findings.
 */
export const ScanConfigSchema = z
  .object({
    /** Path to the Target Model file (YAML/TOML/TS). */
    target: z.string(),
    /** Deterministic seed; if absent the engine generates and records one. */
    seed: z.string().optional(),
    /** Explicit durable local checkpoint; existing files require resume: true. */
    checkpoint: z.string().min(1).optional(),
    resume: z.boolean().default(false),
    /** Probe families/ids to include; empty = all applicable. */
    include: z.array(z.string()).default([]),
    /** Probe families/ids to exclude. */
    exclude: z.array(z.string()).default([]),
    /** Directories/packages to load probes from, in addition to the standard lib. */
    probePaths: z.array(z.string()).default([]),
    /** Declarative external workers; their code is never imported into the host. */
    isolatedProbes: z.array(IsolatedProbeSchema).default([]),
    /** Bounded concurrency for probe execution (spec §4.1). Conservative default. */
    concurrency: z.number().int().positive().default(2),
    /** Total-request ceiling for the whole scan (spec §4.2 runaway control). */
    maxTotalRequests: z.number().int().positive().default(1000),
    /** Wall-clock ceiling for the whole scan, seconds (spec §4.2). */
    maxWallClockSeconds: z.number().int().positive().default(600),
    /** Opt-in to mutating/idempotent-write probes (spec §3.1). Off by default. */
    allowMutating: z.boolean().default(false),
    /** Opt-in to bounded time-based injection probes (spec §3.3). Off by default. */
    allowTimeBased: z.boolean().default(false),
    /** Output artifact paths. */
    output: z
      .object({
        json: z.string().default("findings.json"),
        markdown: z.string().default("report.md"),
        html: z.string().optional(),
        sarif: z.string().optional(),
        junit: z.string().optional(),
        auditLog: z.string().default("audit.ndjson"),
      })
      .strict()
      .default({}),
    /** Baseline file of accepted/known findings to suppress (spec §8.6). */
    baseline: z.string().optional(),
    /** Severity at or above which the CI gate fails (spec §8.6). */
    failOn: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "none"]).default("HIGH"),
  })
  .strict().refine((config) => !config.resume || !!config.checkpoint, {
    message: "resume requires a checkpoint path", path: ["checkpoint"],
  });

export type ScanConfig = z.infer<typeof ScanConfigSchema>;

export function parseScanConfig(input: unknown): ScanConfig {
  return ScanConfigSchema.parse(input);
}
