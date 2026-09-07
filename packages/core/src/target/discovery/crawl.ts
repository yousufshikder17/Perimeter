import { parse } from "parse5";
import { z } from "zod";
import type { Probe } from "@perimeter/sdk";
import { Orchestrator } from "../../orchestrator.js";
import { parseScanConfig } from "../../config/scan-config.js";
import { ConsoleLogger } from "../../runtime/logger.js";
import type { DiscoveryResult } from "./openapi.js";

const CrawlOptionsSchema = z.object({
  as: z.string().min(1),
  start: z.string().min(1).default("/"),
  maxPages: z.number().int().min(1).max(1000).default(50),
  maxDepth: z.number().int().min(0).max(10).default(3),
  maxWallClockSeconds: z.number().int().min(1).max(3600).default(120),
  auditLog: z.string().min(1).default("crawl-audit.ndjson"),
}).strict();

export type CrawlOptions = z.input<typeof CrawlOptionsSchema>;

/** GET-only, same-origin discovery through the normal authorized scan runtime. */
export async function discoverFromCrawl(
  target: string, input: CrawlOptions, signal?: AbortSignal,
): Promise<DiscoveryResult> {
  const options = CrawlOptionsSchema.parse(input);
  const result: DiscoveryResult = { endpoints: [], reviewNotes: [
    "Draft only: authenticated access does not prove authentication is required. Review auth, tenancy, ownership, and concrete resource paths before scanning.",
    "GET-only discovery: no JavaScript, forms, assets, query-bearing URLs, or external origins. GET handlers must be safe for your test identity.",
  ] };
  const notes = new Set<string>();
  const probe: Probe = {
    manifest: {
      id: "discovery/authenticated-crawl", family: "discovery", version: "0.1.0", schemaVersion: "1",
      // No identity requirements: discovery must not provision scratch fixtures.
      requires: {}, safety: { class: "read-only", maxRequests: options.maxPages, destructive: false },
    },
    async plan(ctx) {
      if (!ctx.target.identities.some((identity) => identity.ref === options.as)) {
        throw new Error("Crawl identity is not in the Target Model");
      }
      const base = new URL(ctx.target.baseUrl);
      const start = new URL(options.start, base);
      if (!/^https?:$/.test(base.protocol) || base.username || base.password ||
          start.origin !== base.origin || start.username || start.password || start.search) {
        throw new Error("Crawl start must be an HTTP(S) target-origin URL without credentials or a query");
      }
      return { probeId: this.manifest.id, steps: [{ id: "crawl", description: "Discover linked GET paths", estimatedRequests: options.maxPages }] };
    },
    async run(_plan, ctx) {
      const origin = new URL(ctx.target.baseUrl).origin;
      const queue: Array<{ url: URL; depth: number }> = [];
      const seen = new Set<string>();
      const enqueue = (href: string, base: URL, depth: number) => {
        let url: URL;
        try { url = new URL(href, base); } catch { return; }
        if (url.origin !== origin || url.username || url.password) return;
        if (url.search) { notes.add("Query-bearing links were omitted; review them manually."); return; }
        url.hash = "";
        if (seen.has(url.href)) return;
        if (depth > options.maxDepth) { notes.add("Depth limit reached; inventory is partial."); return; }
        if (queue.length >= options.maxPages) { notes.add("Page limit reached; inventory is partial."); return; }
        seen.add(url.href);
        queue.push({ url, depth });
      };
      enqueue(options.start, new URL(ctx.target.baseUrl), 0);
      for (let index = 0; index < queue.length; index++) {
        ctx.signal.throwIfAborted();
        const { url, depth } = queue[index]!;
        const response = await ctx.http.get(url.href, { as: options.as });
        if (response.status === 401 || response.status === 403) {
          throw new Error("Crawl access denied (401/403); check the configured identity");
        }
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          if (response.headers.location) enqueue(response.headers.location, url, depth + 1);
          notes.add("Redirect responses were not inventoried; only in-scope destinations may be visited.");
          continue;
        }
        if (response.status < 200 || response.status >= 300) {
          notes.add("Non-success responses were omitted; inventory is partial.");
          continue;
        }
        result.endpoints.push({
          id: `crawl_get_${result.endpoints.length + 1}`, method: "GET", path: url.pathname,
          auth: "optional", tenantScoped: false, rateSensitive: false,
        });
        const type = response.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
        if (type === "text/html") {
          const document = parse(await response.text());
          const nodes = [...document.childNodes];
          for (let n = 0; n < nodes.length; n++) {
            const node = nodes[n]!;
            if ("childNodes" in node) nodes.push(...node.childNodes);
          }
          let linkBase = url;
          const base = nodes.find((node) => "tagName" in node && node.tagName === "base" && node.attrs.some((attr) => attr.name === "href"));
          if (base && "attrs" in base) {
            try { linkBase = new URL(base.attrs.find((attr) => attr.name === "href")!.value, url); } catch { /* Invalid base: retain the response URL. */ }
          }
          for (const node of nodes) {
            if ("tagName" in node && (node.tagName === "a" || node.tagName === "area")) {
              const href = node.attrs.find((attr) => attr.name === "href")?.value;
              if (href) enqueue(href, linkBase, depth + 1);
            }
          }
        } else if (type === "application/json" || type?.endsWith("+json")) {
          let data: unknown;
          try { data = await response.json(); } catch { notes.add("Invalid JSON prevented link discovery on a response."); continue; }
          const values: unknown[] = [data];
          for (let n = 0; n < values.length; n++) {
            const value = values[n];
            if (!value || typeof value !== "object") continue;
            for (const [key, child] of Object.entries(value)) {
              if ((key === "href" || key === "url") && typeof child === "string") enqueue(child, url, depth + 1);
              else if (child && typeof child === "object") values.push(child);
            }
          }
        }
      }
    },
  };
  const registry = await new Orchestrator(parseScanConfig({
    target, concurrency: 1, maxTotalRequests: options.maxPages * 2,
    maxWallClockSeconds: options.maxWallClockSeconds, output: { auditLog: options.auditLog },
  }), [probe], {
    logger: new ConsoleLogger("warn"), maxResponseBytes: 1024 * 1024, captureBodies: false,
    ...(signal ? { signal } : {}),
  }).run();
  if (registry.skipped.length) throw new Error(`Discovery failed: ${registry.skipped[0]!.reason}`);
  result.reviewNotes.push(...notes);
  return result;
}
