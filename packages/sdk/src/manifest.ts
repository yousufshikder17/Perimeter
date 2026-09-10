import { z } from "zod";

/**
 * Probe manifest — static identity & requirements (spec §3.1).
 *
 * The manifest is *pure data*: the core can list and validate probes without
 * executing them. It declares which Target Model capabilities the probe needs,
 * its safety classification, and its config schema.
 */

/**
 * Vulnerability class a probe belongs to. Open set (spec §3.3): the five MVP
 * families ship in-repo, but community families drop in the same way and nothing
 * in the engine special-cases a name — so the schema accepts any string, with
 * the standard families documented in `KNOWN_FAMILIES`.
 */
export const KNOWN_FAMILIES = [
  "tenant-isolation",
  "idor",
  "injection",
  "auth",
  "rate-limit",
  "graphql",
  "csv",
] as const;
export const ProbeFamily = z.string();
export type ProbeFamily = z.infer<typeof ProbeFamily>;

/**
 * Safety classification (spec §3.1). The core REJECTS `destructive: true` or a
 * `class` of "mutating" unless the operator passes `--allow-mutating` AND the
 * Target Model authorization block opts in. The standard library ships zero
 * mutating probes.
 */
export const SafetyClass = z.enum([
  "read-only",
  "idempotent-write",
  "mutating",
]);
export type SafetyClass = z.infer<typeof SafetyClass>;

export const ProbeSafetySchema = z.object({
  /** Highest-privilege operation this probe may perform. */
  class: SafetyClass,
  /** Per-invocation request budget; the engine enforces this ceiling (spec §4.1). */
  maxRequests: z.number().int().positive(),
  /** MUST be false for core/standard-library acceptance (spec §3.1). */
  destructive: z.boolean().default(false),
});
export type ProbeSafety = z.infer<typeof ProbeSafetySchema>;

/**
 * Capabilities the Target Model must satisfy for this probe to apply (spec §3.1).
 * Matched against the endpoint inventory annotations (spec §5.3). Unsatisfied
 * probes are skipped with an explicit reason, never silently (spec §2.2).
 */
export const ProbeRequiresSchema = z
  .object({
    /** Minimum number of modeled tenants (e.g. 2 for cross-tenant checks). */
    minTenants: z.number().int().nonnegative().optional(),
    /** Identity refs the probe needs minted, e.g. ["tenantA.user", "tenantB.user"]. */
    identities: z.array(z.string()).optional(),
    /** Opt in to every modeled identity, for target-configured identity pairs. */
    allIdentities: z.boolean().optional(),
    /**
     * Endpoint capability tags the target must expose, expressed in terms of
     * the semantic annotations (spec §5.3): e.g. "readsTenantScopedObject",
     * "createsObject", "rateSensitive", "injectableInput", "authRequired".
     */
    endpoints: z.array(z.string()).optional(),
  })
  .strict();
export type ProbeRequires = z.infer<typeof ProbeRequiresSchema>;

export const ProbeManifestSchema = z
  .object({
    /** Stable id, "<family>/<name>", e.g. "tenant-isolation/cross-tenant-read". */
    id: z.string().regex(/^[a-z0-9-]+\/[a-z0-9-]+$/),
    family: ProbeFamily,
    version: z.string(),
    /** Finding-schema major version this probe emits (spec §6.1). */
    schemaVersion: z.string(),
    /** External execution must be configured declaratively, never imported on the host. */
    isolation: z.literal("subprocess").optional(),
    requires: ProbeRequiresSchema.default({}),
    safety: ProbeSafetySchema,
    /** Path to a JSON Schema / Zod config schema, or inline JSON Schema. */
    configSchema: z.union([z.string(), z.record(z.unknown())]).optional(),
  })
  .strict();
export type ProbeManifest = z.infer<typeof ProbeManifestSchema>;

/** Parse & validate an untrusted manifest (from probe.json or a TS object). */
export function parseManifest(input: unknown): ProbeManifest {
  return ProbeManifestSchema.parse(input);
}
