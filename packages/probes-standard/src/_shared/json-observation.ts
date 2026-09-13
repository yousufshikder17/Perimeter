import type { HttpExchange } from "@perimeter/sdk";

/** Only complete, uncached captured JSON can support a protected-scalar comparison. */
export function observeJson(exchange: HttpExchange, path: string[]): { value: string | number | undefined } | undefined {
  const { body, headers } = exchange.response;
  if (body === undefined || body.includes("«redacted»") || body.includes("«truncated»") || Number(headers.age ?? 0) > 0 ||
      !/^application\/json(?:\s*;|$)/i.test(headers["content-type"] ?? "")) return undefined;
  try {
    let value: unknown = JSON.parse(body);
    for (const key of path) value = value !== null && typeof value === "object" && Object.hasOwn(value, key)
      ? (value as Record<string, unknown>)[key] : undefined;
    return { value: typeof value === "string" && value.trim() ? value :
      typeof value === "number" && Number.isFinite(value) ? value : undefined };
  } catch { return undefined; }
}
