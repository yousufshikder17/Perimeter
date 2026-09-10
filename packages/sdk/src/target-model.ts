import { z } from "zod";
import { Kind, parse, visit } from "graphql";
import type { GuardedRequest } from "./context.js";

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
    /** Pre-issued, signed expired JWT for the same principal; never inline. */
    expiredCredentials: z.object({ env: z.string().min(1) }).strict().optional(),
  })
  .strict();
export type IdentitySpec = z.infer<typeof IdentitySpecSchema>;

export const AuthModelSchema = z
  .object({
    scheme: AuthScheme,
    tokenEndpoint: z.string().optional(),
    /** Explicit contract for a session-cookie login; credentials.env contains JSON fields. */
    login: z.object({
      format: z.enum(["json", "form"]),
      cookieName: z.string().regex(/^[A-Za-z0-9_-]+$/),
    }).strict().optional(),
    refresh: z
      .object({ endpoint: z.string().optional(), ttlSeconds: z.number().int().positive() })
      .strict()
      .optional(),
    /** Module path to a TS hook returning a credential, for `scheme: custom`. */
    customHook: z.string().optional(),
  })
  .strict()
  .superRefine((auth, ctx) => {
    if (auth.scheme === "oauth2_password" && !auth.tokenEndpoint) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["tokenEndpoint"], message: "OAuth password exchange requires tokenEndpoint" });
    }
    if ((auth.login && (auth.scheme !== "session_cookie" || !auth.tokenEndpoint)) ||
        (auth.scheme === "session_cookie" && auth.tokenEndpoint && !auth.login)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["login"], message: "session login requires scheme session_cookie, tokenEndpoint, and login format/cookieName" });
    }
    if (auth.refresh && auth.scheme !== "custom" && !auth.refresh.endpoint) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "refresh.endpoint is required for non-custom authentication",
        path: ["refresh", "endpoint"],
      });
    }
  });
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

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() => z.union([
  z.string(), z.number().finite(), z.boolean(), z.null(),
  z.array(JsonValueSchema), z.record(JsonValueSchema),
]));

/** Reviewed, small query documents only; no batching, fragments, or directives. */
export const GraphqlQuerySchema = z.string().min(1).max(8192).superRefine((query, ctx) => {
  try {
    const document = parse(query, { maxTokens: 1000 });
    const operation = document.definitions[0];
    if (document.definitions.length !== 1 || operation?.kind !== Kind.OPERATION_DEFINITION || operation.operation !== "query") throw new Error();
    let depth = 0;
    let fields = 0;
    visit(document, {
      SelectionSet: { enter() { if (++depth > 8) throw new Error(); }, leave() { depth--; } },
      Field() { if (++fields > 50) throw new Error(); },
      FragmentSpread() { throw new Error(); },
      InlineFragment() { throw new Error(); },
      Directive() { throw new Error(); },
    });
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "GraphQL requires one bounded query (depth <=8, fields <=50), without fragments or directives" });
  }
});

export const GraphqlModelSchema = z.object({
  query: GraphqlQuerySchema,
  variables: z.record(JsonValueSchema).default({}),
  /** Relative to response.data; must select a protected, distinguishing scalar. */
  resultPath: z.array(z.string().min(1)).min(1).max(8),
  ownerIdentity: IdentityRef,
  otherIdentity: IdentityRef,
}).strict();

export const EndpointSchema = z
  .object({
    id: z.string(),
    method: HttpMethod,
    path: z.string(),
    /** A reviewed GraphQL query transported by GET or POST, not a REST route. */
    graphql: GraphqlModelSchema.optional(),
    /** Reviewed CSV export of an engine-created harmless formula canary. */
    csv: z.object({
      identity: IdentityRef,
      column: z.string().min(1),
      idColumn: z.string().min(1),
      fixtureField: z.string().min(1),
      delimiter: z.enum([",", ";", "\t"]).default(","),
      canary: z.enum(["=1+1", "+1+1", "-1+1", "@SUM(1,1)"]).default("=1+1"),
    }).strict().optional(),
    /** Must enforce tenant isolation → tenant-isolation probe target. */
    tenantScoped: z.boolean().default(false),
    /** Present → IDOR probe target. */
    objectRef: ObjectRefSchema.optional(),
    /** Logical kind this endpoint creates → usable as a scratch-fixture factory. */
    creates: z.string().optional(),
    /** Static, non-secret JSON data used to provision a scratch object. */
    fixture: z.object({
      body: z.record(JsonValueSchema).optional(),
      /** Exact JSON keys leading to the created object's ID; no heuristic fallback. */
      responseIdPath: z.array(z.string().min(1)).min(1).optional(),
    }).strict().optional(),
    /** Present → rate-limit probe target. */
    rateSensitive: z.boolean().default(false),
    /** Input fields that reach an interpreter → injection probe surface. */
    injectable: z.array(z.string()).optional(),
    /** Whether auth is required to call this endpoint. */
    auth: z.enum(["required", "optional", "none"]).default("required"),
  })
  .strict()
  .superRefine((endpoint, ctx) => {
    if (endpoint.csv && (endpoint.method !== "GET" || endpoint.graphql || !endpoint.objectRef ||
        endpoint.creates || endpoint.csv.column === endpoint.csv.idColumn ||
        !/^\/(?!\/)[^?#\\]*$/.test(endpoint.path) ||
        /[{}]/.test(endpoint.path.replace(`{${endpoint.objectRef?.param}}`, "scratch")))) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["csv"], message: "CSV requires a GET export, distinct data/ID columns, objectRef, and an origin-relative path with at most its object ID placeholder" });
    }
    if (endpoint.graphql) {
      if (!["GET", "POST"].includes(endpoint.method) || !/^\/(?!\/)[^?#{}]*$/.test(endpoint.path) || endpoint.creates || endpoint.fixture) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["graphql"], message: "GraphQL needs GET/POST and a literal origin-relative path, with no factory annotations" });
      }
      if (endpoint.objectRef) {
        try {
          const operation = parse(endpoint.graphql.query).definitions[0];
          if (operation?.kind !== Kind.OPERATION_DEFINITION || !operation.variableDefinitions?.some((v) => v.variable.name.value === endpoint.objectRef!.param)) throw new Error();
        } catch {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["objectRef"], message: "GraphQL objectRef.param must name a declared query variable" });
        }
      }
    }
    if (endpoint.fixture && (!endpoint.creates?.trim() || endpoint.method !== "POST")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["fixture"],
        message: "fixture configuration requires a POST endpoint with creates",
      });
    }
  });
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
    for (const endpoint of model.endpoints.filter((e) => e.csv)) {
      const csv = endpoint.csv!;
      const factories = model.endpoints.filter((e) => e.creates === endpoint.objectRef?.kind);
      if (!model.identities.some((i) => i.ref === csv.identity) || factories.length !== 1 ||
          factories[0]?.method !== "POST" || factories[0]?.fixture?.body?.[csv.fixtureField] !== csv.canary) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["endpoints"], message: "CSV requires a modeled identity and one POST scratch factory whose fixture field equals the harmless canary" });
      }
    }
    for (const endpoint of model.endpoints) {
      if (!endpoint.graphql) continue;
      const owner = model.identities.find((i) => i.ref === endpoint.graphql!.ownerIdentity);
      const other = model.identities.find((i) => i.ref === endpoint.graphql!.otherIdentity);
      if (!owner || !other || owner.ref === other.ref || (endpoint.tenantScoped && owner.tenant === other.tenant)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["endpoints"], message: "GraphQL needs distinct modeled owner/other identities (different tenants when tenantScoped)" });
      }
    }
    if (model.auth.scheme === "oauth2_password" || model.auth.login) {
      for (const endpoint of [model.auth.tokenEndpoint, model.auth.refresh?.endpoint]) {
        if (!endpoint) continue;
        try {
          const url = new URL(endpoint, model.baseUrl);
          if (url.origin !== new URL(model.baseUrl).origin || url.username || url.password || url.hash) throw new Error();
        } catch {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["auth"], message: "authentication endpoints must stay on the target origin without userinfo or fragments" });
        }
      }
    }
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

/** Reuses guarded HTTP: GraphQL never introduces another network client. */
export function graphqlRequest(endpoint: Endpoint, variables = endpoint.graphql?.variables): GuardedRequest {
  if (!endpoint.graphql) throw new Error("Endpoint has no GraphQL query");
  const envelope = { query: endpoint.graphql.query, variables: variables ?? {} };
  return {
    method: endpoint.method,
    url: endpoint.method === "GET" ? `${endpoint.path}?${new URLSearchParams({ query: envelope.query, variables: JSON.stringify(envelope.variables) })}` : endpoint.path,
    ...(endpoint.method === "POST" ? { body: JSON.stringify(envelope) } : {}),
    headers: { accept: "application/graphql-response+json, application/json", "content-type": "application/json" },
    maxResponseBytes: 65536,
  };
}
