import { readFile } from "node:fs/promises";
import type { HttpMethod } from "@perimeter/sdk";
import type { DiscoveryResult, DraftEndpoint } from "./openapi.js";

const METHODS = new Set<HttpMethod>(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

/** Imports a review-required endpoint draft from a Postman Collection v2.x file. */
export async function discoverFromPostman(collectionPath: string): Promise<DiscoveryResult> {
  const parsed: unknown = JSON.parse(await readFile(collectionPath, "utf8"));
  if (!isRecord(parsed) || !Array.isArray(parsed.item)) {
    throw new Error("Invalid Postman collection: expected a top-level item array");
  }

  const endpoints: DraftEndpoint[] = [];
  const reviewNotes: string[] = [];
  const seen = new Set<string>();

  visitItems(parsed.item, authType(parsed.auth), (item, inheritedAuth) => {
    const request = isRecord(item.request) ? item.request : undefined;
    const method = typeof request?.method === "string" ? request.method.toUpperCase() : "";
    const path = pathFromUrl(request?.url);
    if (!METHODS.has(method as HttpMethod) || !path) {
      reviewNotes.push(`${itemName(item)}: skipped because method or URL is unsupported`);
      return;
    }

    const key = `${method} ${path}`;
    if (seen.has(key)) return;
    seen.add(key);

    const id = `${method.toLowerCase()}_${path.replace(/[^a-z0-9]+/gi, "_").replace(/^_|_$/g, "")}`;
    const endpoint: DraftEndpoint = {
      id,
      method: method as HttpMethod,
      path,
      auth: toEndpointAuth(authType(request?.auth) ?? inheritedAuth),
      tenantScoped: false,
      rateSensitive: /login|token|otp|auth/i.test(path),
    };

    const pathParam = /\{(\w+)\}/.exec(path)?.[1];
    if (method === "GET" && pathParam) {
      endpoint._inferred = {
        tenantScoped: "single-id GET — confirm if tenant-scoped",
        objectRef: `param "${pathParam}" — confirm object kind & ownership`,
      };
      reviewNotes.push(`${id}: confirm objectRef ownership for path param "${pathParam}"`);
    }
    if (endpoint.rateSensitive) {
      reviewNotes.push(`${id}: marked rateSensitive by name heuristic — confirm`);
    }
    reviewNotes.push(`${id}: confirm imported authentication requirement`);
    endpoints.push(endpoint);
  });

  return { endpoints, reviewNotes };
}

function visitItems(
  items: unknown[],
  inheritedAuth: string | undefined,
  visit: (item: Record<string, unknown>, auth: string | undefined) => void,
): void {
  for (const value of items) {
    if (!isRecord(value)) continue;
    const auth = authType(value.auth) ?? inheritedAuth;
    if (Array.isArray(value.item)) visitItems(value.item, auth, visit);
    else visit(value, auth);
  }
}

function pathFromUrl(value: unknown): string | undefined {
  if (typeof value === "string") return normalizePath(value);
  if (!isRecord(value)) return undefined;
  if (Array.isArray(value.path) && value.path.every((part) => typeof part === "string")) {
    return normalizePath(`/${value.path.join("/")}`);
  }
  return typeof value.raw === "string" ? normalizePath(value.raw) : undefined;
}

function normalizePath(raw: string): string | undefined {
  const withoutVariableHost = raw.replace(/^\{\{[^}]+\}\}/, "");
  let path: string;
  try {
    path = new URL(withoutVariableHost).pathname;
  } catch {
    path = withoutVariableHost.split(/[?#]/, 1)[0] ?? "";
  }
  if (!path) return undefined;
  if (!path.startsWith("/")) path = `/${path}`;
  return path.replace(/\/:([A-Za-z0-9_]+)/g, "/{$1}");
}

function authType(value: unknown): string | undefined {
  return isRecord(value) && typeof value.type === "string" ? value.type : undefined;
}

function toEndpointAuth(type: string | undefined): "required" | "optional" | "none" {
  if (type === "noauth") return "none";
  return type ? "required" : "optional";
}

function itemName(item: Record<string, unknown>): string {
  return typeof item.name === "string" ? item.name : "unnamed item";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
