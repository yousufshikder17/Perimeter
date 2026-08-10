import { pathToFileURL } from "node:url";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { Store, vulnsFromEnv } from "./store.js";

/**
 * Deliberately-vulnerable reference SaaS (spec §9). A Hono/TypeScript API over a
 * shared, tenant-discriminated store — the analog of the audit's shared Postgres
 * + RLS. Probes run end-to-end against this with zero external dependencies.
 *
 * ⚠ NEVER deploy this. It intentionally leaks across tenants by default.
 */
const store = new Store();
const vulns = vulnsFromEnv();
const app = new Hono();

/**
 * Toy auth: `Authorization: Bearer <tenant>:<user>`. Real targets use the
 * Target Model's auth recipe; this keeps the fixture dependency-free.
 */
function principal(auth: string | undefined): { tenant: string; user: string } | null {
  const m = /^Bearer\s+([\w-]+):([\w-]+)$/.exec(auth ?? "");
  return m ? { tenant: m[1]!, user: m[2]! } : null;
}

app.get("/healthz", (c) => c.json({ ok: true, vulns }));

// Tenant-scoped object read — the cross-tenant-read / IDOR probe target.
app.get("/api/invoices/:invoiceId", (c) => {
  const who = principal(c.req.header("authorization"));
  if (!who && !vulns.missingAuth) return c.json({ error: "unauthorized" }, 401);

  const callerTenant = who?.tenant ?? "tenant-a";
  const inv = store.getInvoice(c.req.param("invoiceId"), callerTenant, vulns);
  if (!inv) return c.json({ error: "not found" }, 404);
  return c.json(inv);
});

// Scratch-fixture factory — used by the engine to create tenant-owned objects.
app.post("/api/invoices", async (c) => {
  const who = principal(c.req.header("authorization"));
  if (!who) return c.json({ error: "unauthorized" }, 401);
  const body = (await c.req.json().catch(() => ({}))) as { amountCents?: number; memo?: string };
  const inv = store.create({
    tenantId: who.tenant,
    ownerUserId: who.user,
    amountCents: body.amountCents ?? 0,
    memo: body.memo ?? "scratch",
  });
  return c.json(inv, 201);
});

// Rate-sensitive endpoint — the rate-limit probe target. A real gateway throttles
// by path + client regardless of HTTP method, so the cheap read-only HEAD burst the
// rate-limit probe issues is counted too (spec §3.3). The throttle lives in path
// middleware, not the POST handler, so it applies to every method on the path.
let loginHits = 0;
app.use("/auth/login", async (c, next) => {
  loginHits++;
  if (!vulns.noRateLimit && loginHits % 10 === 0) {
    return c.json({ error: "too many requests" }, 429, { "retry-after": "1" });
  }
  return next();
});
app.post("/auth/login", (c) => c.json({ token: "Bearer tenant-a:user-a" }));
// Cheap, read-only surface for the rate-limit probe's bounded burst.
app.on(["GET", "HEAD"], "/auth/login", (c) => c.body(null, 200));

/**
 * Start the reference target. `port: 0` binds an ephemeral port; the resolved
 * port is returned so tests can address it. Vulnerabilities are read from the
 * environment at module load (see `vulnsFromEnv`), so set any `FIX_*` / `BREAK_*`
 * flags before importing this module.
 */
export function start(
  port = Number(process.env.PORT ?? 8080),
): Promise<{ server: ReturnType<typeof serve>; port: number }> {
  return new Promise((resolvePromise) => {
    const server = serve({ fetch: app.fetch, port }, (info) => {
      console.log(`reference-target listening on :${info.port} (vulns: ${JSON.stringify(vulns)})`);
      resolvePromise({ server, port: info.port });
    });
  });
}

// Auto-start only when executed directly (`node dist/server.js`), never on import,
// so the e2e test can control the port and lifecycle itself.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  void start();
}

export { app };
