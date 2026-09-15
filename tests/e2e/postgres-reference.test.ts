import { describe, expect, it } from "vitest";
import { createApp } from "../../apps/reference-target/dist/server.js";
import { Store } from "../../apps/reference-target/dist/store.js";
import { PostgresStore } from "../../apps/reference-target/dist/postgres-store.js";
import { postgresEnabled, postgresFixture } from "../fixtures/postgres.js";

const patched = { crossTenantRead: false, idor: false, missingAuth: false, noRateLimit: false };
const auth = (tenant: string, user: string) => ({ authorization: "Bearer " + tenant + ":" + user });

it("keeps the memory backend usable and enforces patched ownership", async () => {
  const app = createApp(new Store(), patched);
  expect(
    (await app.request("/api/invoices/inv-a-1", { headers: auth("tenant-a", "user-a") })).status,
  ).toBe(200);
  expect(
    (await app.request("/api/invoices/inv-a-1", { headers: auth("tenant-a", "other") })).status,
  ).toBe(403);
  expect(
    (await app.request("/api/invoices/inv-a-1", { headers: auth("tenant-b", "user-b") })).status,
  ).toBe(404);
  expect((await app.request("/api/invoices/inv-a-1")).status).toBe(401);
});

describe.skipIf(!postgresEnabled)("real PostgreSQL reference target", () => {
  it("enforces RLS, isolates reused connections, rolls back failures, and exposes a broken policy", async () => {
    const fixture = await postgresFixture();
    const store = new PostgresStore(fixture.appUrl);
    try {
      const app = createApp(store, { ...patched, idor: true });
      const read = (tenant: string, id: string) =>
        app.request("/api/invoices/" + id, { headers: auth(tenant, "user-a") });
      expect((await read("tenant-a", "inv-a-1")).status).toBe(200);
      expect((await read("tenant-a", "inv-b-1")).status).toBe(404);
      expect((await read("tenant-b", "inv-b-1")).status).toBe(200);
      expect((await read("tenant-b", "inv-a-1")).status).toBe(404);
      expect(
        await store.withTenant(
          undefined,
          async (c) => (await c.query("SELECT id FROM invoices")).rows,
        ),
      ).toEqual([]);
      await expect(
        store.withTenant("tenant-a", async (c) =>
          c.query("INSERT INTO invoices VALUES ('bad','tenant-b','user-b',0,'bad')"),
        ),
      ).rejects.toThrow("Reference PostgreSQL operation failed");
      expect((await read("tenant-a", "inv-a-1")).status).toBe(200);
      const response = await app.request("/api/invoices", {
        method: "POST",
        headers: { ...auth("tenant-a", "user-a"), "content-type": "application/json" },
        body: JSON.stringify({ amountCents: 1, memo: "scratch" }),
      });
      expect(response.status).toBe(201);
      const scratch = (await response.json()) as { id: string };
      expect((await read("tenant-b", scratch.id)).status).toBe(404);
      await store.withTenant("tenant-a", async (c) =>
        c.query("DELETE FROM invoices WHERE id=$1", [scratch.id]),
      );
      expect((await read("tenant-a", scratch.id)).status).toBe(404);
      await fixture.admin.query("ALTER POLICY invoices_tenant_isolation ON invoices USING (true)");
      expect((await read("tenant-a", "inv-b-1")).status).toBe(200);
    } finally {
      await store.close();
      await fixture.close();
    }
  }, 60000);
});
