import { z } from "zod";
import { ProbeFamily } from "./manifest.js";
import { ObjectRefSchema, IdentityRef } from "./target-model.js";

/**
 * Finding schema (spec §6) — the machine contract.
 *
 * Principles: schema-first & versioned, evidence is non-optional, actionable
 * (severity + remediation required), stable fingerprint for CI diffing.
 */

/** Bump the MAJOR when the shape changes incompatibly; probes declare what they emit. */
export const FINDING_SCHEMA_VERSION = "1.0" as const;

export const Severity = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
export type Severity = z.infer<typeof Severity>;

export const Confidence = z.enum(["CONFIRMED", "FIRM", "TENTATIVE"]);
export type Confidence = z.infer<typeof Confidence>;

export const FindingStatus = z.enum([
  "open",
  "accepted",
  "fixed",
  "suppressed",
]);
export type FindingStatus = z.infer<typeof FindingStatus>;

// ---------------------------------------------------------------------------
// 6.3 Evidence bundle — mandatory for every finding
// ---------------------------------------------------------------------------

export const HttpExchangeSchema = z
  .object({
    /** Opaque id, referenceable from `differential` and the audit log. */
    ref: z.string(),
    request: z.object({
      method: z.string(),
      url: z.string(),
      headers: z.record(z.string()), // secrets redacted on capture
      body: z.string().optional(), // size-bounded, redacted
    }),
    response: z.object({
      status: z.number().int(),
      headers: z.record(z.string()),
      body: z.string().optional(), // size-bounded, redacted
      elapsedMs: z.number().nonnegative().optional(),
    }),
    /** Which identity/tenant this exchange was issued under. */
    issuedAs: IdentityRef.optional(),
  })
  .strict();
export type HttpExchange = z.infer<typeof HttpExchangeSchema>;

export const EvidenceSchema = z
  .object({
    summary: z.string(), // one-line "what proves this"
    exchanges: z.array(HttpExchangeSchema).min(1),
    differential: z
      .object({
        baseline: z.string(), // ExchangeRef
        probe: z.string(), // ExchangeRef
        diff: z.string(),
      })
      .strict()
      .optional(),
    reproduction: z
      .object({
        seed: z.string(),
        steps: z.array(z.string()),
        curl: z.array(z.string()).optional(), // redacted creds
      })
      .strict(),
    /** Content-addressed pointers into the append-only audit log (spec §4.1). */
    auditRefs: z.array(z.string()),
  })
  .strict();
export type Evidence = z.infer<typeof EvidenceSchema>;

// ---------------------------------------------------------------------------
// 6.4 Remediation — mandatory, authored per probe
// ---------------------------------------------------------------------------

export const RemediationSchema = z
  .object({
    guidance: z.string(), // class-specific, concrete
    references: z.array(z.string()), // OWASP/CWE links, framework docs
    codeHints: z.array(z.string()).optional(),
    effort: z.enum(["trivial", "moderate", "significant"]).optional(),
  })
  .strict();
export type Remediation = z.infer<typeof RemediationSchema>;

// ---------------------------------------------------------------------------
// 6.2 Finding object
// ---------------------------------------------------------------------------

export const FindingTargetSchema = z
  .object({
    endpointId: z.string(),
    method: z.string(),
    path: z.string(),
    tenantScoped: z.boolean().optional(),
    objectRef: ObjectRefSchema.optional(),
  })
  .strict();

export const FindingSchema = z
  .object({
    id: z.string(), // ULID
    fingerprint: z.string(), // stable hash(probeId + endpoint + class + locator)
    schemaVersion: z.string(),
    probeId: z.string(),
    family: ProbeFamily,
    title: z.string(),

    severity: Severity,
    confidence: Confidence,
    cwe: z.array(z.string()).optional(),
    owaspApi: z.array(z.string()).optional(),

    target: FindingTargetSchema,
    affectedIdentities: z.array(IdentityRef),

    evidence: EvidenceSchema, // mandatory (spec §6.2)
    remediation: RemediationSchema, // mandatory

    firstSeen: z.string(), // ISO-8601
    lastSeen: z.string(),
    status: FindingStatus.default("open"),
  })
  .strict();
export type Finding = z.infer<typeof FindingSchema>;

/**
 * A `Pass` is an explicit non-finding (spec §2.2, §6). Probes emit passes so the
 * report can show "login IS rate-limited" rather than silent absence.
 */
export const PassSchema = z
  .object({
    kind: z.literal("pass"),
    probeId: z.string(),
    family: ProbeFamily,
    title: z.string(),
    endpointId: z.string().optional(),
    summary: z.string(),
  })
  .strict();
export type Pass = z.infer<typeof PassSchema>;

export type Report = Finding | Pass;

export function parseFinding(input: unknown): Finding {
  return FindingSchema.parse(input);
}

/** Full registry export — the JSON machine contract (spec §6.5). */
export const FindingRegistrySchema = z
  .object({
    schemaVersion: z.string(),
    scanId: z.string(),
    target: z.string(),
    seed: z.string(),
    startedAt: z.string(),
    finishedAt: z.string(),
    findings: z.array(FindingSchema),
    passes: z.array(PassSchema),
    /** Probes skipped because requirements were unmet — never silent (spec §2.2). */
    skipped: z.array(
      z.object({ probeId: z.string(), reason: z.string() }).strict(),
    ),
  })
  .strict();
export type FindingRegistry = z.infer<typeof FindingRegistrySchema>;
