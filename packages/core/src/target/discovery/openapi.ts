import SwaggerParser from "@apidevtools/swagger-parser";
import type { Endpoint, HttpMethod } from "@perimeter/sdk";

/**
 * OpenAPI discovery (spec §5.4). Bootstraps a *draft* endpoint inventory from an
 * OpenAPI/Swagger spec — annotations are *inferred*, then reviewed and refined
 * by the user. The platform never guesses ownership semantics silently: inferred
 * `objectRef`/`tenantScoped` come out as suggestions the user confirms.
 *
 * HAR/Postman/authenticated-crawl discovery is sequenced next (spec §8, §10).
 */

export interface DiscoveryResult {
  endpoints: DraftEndpoint[];
  /** Human notes the reviewer must resolve before the model is trustworthy. */
  reviewNotes: string[];
}

/** An endpoint plus provenance markers, pending human review. */
export interface DraftEndpoint extends Endpoint {
  _inferred?: {
    tenantScoped?: string;
    objectRef?: string;
  };
}

const METHODS: HttpMethod[] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

export async function discoverFromOpenApi(specPath: string): Promise<DiscoveryResult> {
  const api = (await SwaggerParser.dereference(specPath)) as OpenApiDoc;
  const endpoints: DraftEndpoint[] = [];
  const reviewNotes: string[] = [];

  for (const [path, item] of Object.entries(api.paths ?? {})) {
    for (const method of METHODS) {
      const op = item?.[method.toLowerCase() as Lowercase<HttpMethod>];
      if (!op) continue;

      const id = op.operationId ?? `${method.toLowerCase()}_${path.replace(/[^a-z0-9]+/gi, "_")}`;
      const pathParam = /\{(\w+)\}/.exec(path)?.[1];

      const endpoint: DraftEndpoint = {
        id,
        method,
        path,
        auth: op.security?.length ? "required" : "optional",
        tenantScoped: false,
        rateSensitive: false,
      };

      // Heuristic: a GET with a single {id}-style path param is a likely IDOR /
      // tenant-scoped read target — flag for review rather than assume ownership.
      if (method === "GET" && pathParam) {
        endpoint._inferred = {
          tenantScoped: "single-id GET — confirm if tenant-scoped",
          objectRef: `param "${pathParam}" — confirm object kind & ownership`,
        };
        reviewNotes.push(`${id}: confirm objectRef ownership for path param "${pathParam}"`);
      }
      if (/login|token|otp|auth/i.test(path)) {
        endpoint.rateSensitive = true;
        reviewNotes.push(`${id}: marked rateSensitive by name heuristic — confirm`);
      }
      endpoints.push(endpoint);
    }
  }
  return { endpoints, reviewNotes };
}

// Minimal structural typing over the parsed doc (we only read what we need).
interface OpenApiDoc {
  paths?: Record<string, Record<string, OpenApiOperation | undefined> | undefined>;
}
interface OpenApiOperation {
  operationId?: string;
  security?: unknown[];
}
