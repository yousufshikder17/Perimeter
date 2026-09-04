import { readFile } from "node:fs/promises";
import type { HttpMethod } from "@perimeter/sdk";
import type { DiscoveryResult, DraftEndpoint } from "./openapi.js";

const METHODS = new Set<HttpMethod>(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const IDENTIFIER = /^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,})$/i;

/** Imports a review-required endpoint draft from a HAR 1.2 capture. */
export async function discoverFromHar(harPath: string): Promise<DiscoveryResult> {
  const parsed: unknown = JSON.parse(await readFile(harPath, "utf8"));
  const entries = isRecord(parsed) && isRecord(parsed.log) ? parsed.log.entries : undefined;
  if (!Array.isArray(entries)) {
    throw new Error("Invalid HAR: expected log.entries array");
  }

  const endpoints: DraftEndpoint[] = [];
  const reviewNotes: string[] = [];
  const seen = new Set<string>();

  for (const [index, entry] of entries.entries()) {
    const request = isRecord(entry) && isRecord(entry.request) ? entry.request : undefined;
    const method = typeof request?.method === "string" ? request.method.toUpperCase() : "";
    const rawUrl = typeof request?.url === "string" ? request.url : "";
    if (!METHODS.has(method as HttpMethod) || !rawUrl) {
      reviewNotes.push(`entry ${index + 1}: skipped because method or URL is unsupported`);
      continue;
    }

    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      reviewNotes.push(`entry ${index + 1}: skipped invalid URL`);
      continue;
    }

    let templated = false;
    const path =
      "/" +
      url.pathname
        .split("/")
        .filter(Boolean)
        .map((segment) => {
          if (!IDENTIFIER.test(segment)) return segment;
          templated = true;
          return "{id}";
        })
        .join("/");
    const key = `${method} ${path}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const id = `${method.toLowerCase()}_${path.replace(/[^a-z0-9]+/gi, "_").replace(/^_|_$/g, "")}`;
    const endpoint: DraftEndpoint = {
      id,
      method: method as HttpMethod,
      path,
      auth: hasCredentialHeader(request?.headers) ? "required" : "optional",
      tenantScoped: false,
      rateSensitive: /login|token|otp|auth/i.test(path),
    };

    if (templated) {
      endpoint._inferred = {
        tenantScoped: "captured identifier was templated — confirm if tenant-scoped",
        objectRef: 'param "id" — confirm object kind & ownership',
      };
      reviewNotes.push(`${id}: confirm inferred {id} path template and ownership`);
    }
    if (endpoint.rateSensitive) {
      reviewNotes.push(`${id}: marked rateSensitive by name heuristic — confirm`);
    }
    reviewNotes.push(`${id}: confirm authentication requirement inferred from captured headers`);
    endpoints.push(endpoint);
  }

  return { endpoints, reviewNotes };
}

function hasCredentialHeader(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.some(
      (header) =>
        isRecord(header) &&
        typeof header.name === "string" &&
        /^(authorization|cookie|x-api-key)$/i.test(header.name),
    )
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
