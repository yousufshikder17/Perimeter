import { z } from "zod";

/**
 * Target Model (spec §5) — the declarative description of a target's auth model,
 * tenant structure, and annotated endpoint inventory. This is what lets probes
 * reason about *tenants, identities, and object ownership* rather than URLs.
 *
 * Loaded from TOML/YAML/TS. Probes receive a read-only view via ProbeContext.
 */

// ---------------------------------------------------------------------------
// 5.1 Auth model
// ---------------------------------------------------------------------------

export const AuthScheme = z.enum([
  "api_key",
  "bearer",
  "oauth2_password",
  "session_cookie",
  "custom",
]);
export type AuthScheme = z.infer<typeof AuthScheme>;

/** A reference to an identity, e.g. "tenantA.user". */
export const IdentityRef = z.string();
export type IdentityRef = z.infer<typeof IdentityRef>;

export const IdentitySpecSchema = z
  .object({
    ref: IdentityRef,
    tenant: z.string(),
    role: z.string().default("member"),
    /**
     * Secrets are NEVER inline. Credentials are resolved from an env var ref;
     * a `custom` auth scheme resolves them via a user-supplied TS hook.
     */
    credentials: z
      .object({ env: z.string() })
      .strict()
      .optional(),
  })
  .strict();
export type IdentitySpec = z.infer<typeof IdentitySpecSchema>;

export const AuthModelSchema = z
  .object({
    scheme: AuthScheme,
    tokenEndpoint: z.string().optional(),
    refresh: z
      .object({ endpoint: z.string(), ttlSeconds: z.number().int().positive() })
      .strict()
      .optional(),
    /** Module path to a TS hook returning a credential, for `scheme: custom`. */
    customHook: z.string().optional(),
  })
  .strict();
export type AuthModel = z.infer<typeof AuthModelSchema>;

// ---------------------------------------------------------------------------
// 5.2 Tenant structure
// ---------------------------------------------------------------------------

export const TenancyModel = z.enum([
  "shared_db_rls",
  "schema_per_tenant",
  "db_per_tenant",
  "header_scoped",
]);
export type TenancyModel = z.infer<typeof TenancyModel>;

export const DiscriminatorLocation = z.enum([
  "jwt_claim",
  "header",
  "subdomain",
  "path_param",
]);
export type DiscriminatorLocation = z.infer<typeof DiscriminatorLocation>;

export const TenancySchema = z
  .object({
    model: TenancyModel,
    discriminator: z
      .object({ location: DiscriminatorLocation, name: z.string() })
      .strict(),
    /** ≥2 required for isolation probes (spec §5.2). */
    tenants: z.array(z.string()).min(1),
  })
  .strict();
export type Tenancy = z.infer<typeof TenancySchema>;

// ---------------------------------------------------------------------------
// 5.3 Endpoint inventory (with semantic annotations)
// ---------------------------------------------------------------------------

export const HttpMethod = z.enum([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);
export type HttpMethod = z.infer<typeof HttpMethod>;

/** Object-reference annotation making an endpoint an IDOR target (spec §5.3). */
export const ObjectRefSchema = z
  .object({
    /** The parameter carrying the object id (path/query/body). */
    param: z.string(),
    /** Logical object kind, e.g. "invoice". */
    kind: z.string(),
    /** Ownership model — who a given id belongs to. */
    ownership: z.enum(["tenant", "user", "global"]),
  })
  .strict();
export type ObjectRef = z.infer<typeof ObjectRefSchema>;

export const EndpointSchema = z
  .object({
    id: z.string(),
    method: HttpMethod,
    path: z.string(),
    /** Must enforce tenant isolation → tenant-isolation probe target. */
    tenantScoped: z.boolean().default(false),
    /** Present → IDOR probe target. */
    objectRef: ObjectRefSchema.optional(),
    /** Logical kind this endpoint creates → usable as a scratch-fixture factory. */
    creates: z.string().optional(),
    /** Present → rate-limit probe target. */
    rateSensitive: z.boolean().default(false),
    /** Input fields that reach an interpreter → injection probe surface. */
    injectable: z.array(z.string()).optional(),
    /** Whether auth is required to call this endpoint. */
    auth: z.enum(["required", "optional", "none"]).default("required"),
  })
  .strict();
export type Endpoint = z.infer<typeof EndpointSchema>;

// ---------------------------------------------------------------------------
// 5.5 Authorization & safety metadata (mandatory)
// ---------------------------------------------------------------------------

export const RateLimitSchema = z
  .object({
    globalRps: z.number().positive(),
    perHostRps: z.number().positive(),
    burst: z.number().int().positive(),
  })
  .strict();
export type RateLimit = z.infer<typeof RateLimitSchema>;

export const Environment = z.enum(["local", "staging", "production"]);
export type Environment = z.infer<typeof Environment>;

export const AuthorizationSchema = z
  .object({
    /** The engine REFUSES to run if false or absent (spec §5.5). */
    iAmAuthorizedToTest: z.literal(true),
    environment: Environment,
    contact: z.string(),
    rateLimit: RateLimitSchema,
  })
  .strict();
export type Authorization = z.infer<typeof AuthorizationSchema>;

// ---------------------------------------------------------------------------
// Full Target Model
// ---------------------------------------------------------------------------

export const TargetModelSchema = z
  .object({
    name: z.string(),
    /** Base URL(s) of the modeled target — the ONLY hosts egress is allowed to. */
    baseUrl: z.string().url(),
    auth: AuthModelSchema,
    identities: z.array(IdentitySpecSchema).min(1),
    tenancy: TenancySchema,
    endpoints: z.array(EndpointSchema),
    authorization: AuthorizationSchema,
  })
  .strict()
  .superRefine((model, ctx) => {
    // Every identity's tenant must be declared in the tenancy block.
    const declared = new Set(model.tenancy.tenants);
    for (const id of model.identities) {
      if (!declared.has(id.tenant)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `identity "${id.ref}" references undeclared tenant "${id.tenant}"`,
          path: ["identities"],
        });
      }
    }
  });

/** Fully-validated, read-only Target Model handed to probes. */
export type TargetModel = z.infer<typeof TargetModelSchema>;

export function parseTargetModel(input: unknown): TargetModel {
  return TargetModelSchema.parse(input);
}
