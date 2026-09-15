import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { start } from "../../apps/reference-target/dist/server.js";
import { postgresEnabled, postgresFixture } from "../fixtures/postgres.js";

describe.skipIf(!postgresEnabled)("CLI against PostgreSQL reference API", () => {
  it("passes correct RLS and gates a deliberately broken policy", async () => {
    const fixture = await postgresFixture();
    const dir = await mkdtemp(join(tmpdir(), "perimeter-pg-cli-"));
    const previous = process.env.PERIMETER_REFERENCE_DATABASE_URL;
    process.env.PERIMETER_REFERENCE_DATABASE_URL = fixture.appUrl;
    const { server, port } = await start(0);
    try {
      const target = {
        name: "postgres-reference",
        baseUrl: "http://127.0.0.1:" + port,
        auth: { scheme: "bearer", tokenEndpoint: "/auth/login" },
        identities: [
          {
            ref: "tenantA.user",
            tenant: "tenant-a",
            role: "member",
            credentials: { env: "PG_TEST_A" },
          },
          {
            ref: "tenantB.user",
            tenant: "tenant-b",
            role: "member",
            credentials: { env: "PG_TEST_B" },
          },
        ],
        tenancy: {
          model: "shared_db_rls",
          discriminator: { location: "jwt_claim", name: "tenant_id" },
          tenants: ["tenant-a", "tenant-b"],
        },
        endpoints: [
          {
            id: "read",
            method: "GET",
            path: "/api/invoices/{id}",
            auth: "required",
            tenantScoped: true,
            objectRef: { param: "id", kind: "invoice", ownership: "tenant" },
          },
          {
            id: "create",
            method: "POST",
            path: "/api/invoices",
            auth: "required",
            creates: "invoice",
          },
        ],
        authorization: {
          iAmAuthorizedToTest: true,
          environment: "local",
          contact: "test@example.com",
          rateLimit: { globalRps: 20, perHostRps: 20, burst: 20 },
        },
      };
      await writeFile(join(dir, "target.json"), JSON.stringify(target));
      await writeFile(
        join(dir, "scan.json"),
        JSON.stringify({
          target: join(dir, "target.json"),
          include: ["tenant-isolation/cross-tenant-read"],
          output: {
            json: join(dir, "report.json"),
            markdown: join(dir, "report.md"),
            auditLog: join(dir, "audit.ndjson"),
          },
          failOn: "HIGH",
        }),
      );
      const run = () =>
        promisify(execFile)(
          process.execPath,
          ["packages/cli/dist/bin.js", "scan", "--config", join(dir, "scan.json")],
          { env: { ...process.env, PG_TEST_A: "tenant-a:user-a", PG_TEST_B: "tenant-b:user-b" } },
        );
      await run();
      expect(JSON.parse(await readFile(join(dir, "report.json"), "utf8")).findings).toHaveLength(0);
      await fixture.admin.query("ALTER POLICY invoices_tenant_isolation ON invoices USING (true)");
      await expect(run()).rejects.toMatchObject({ code: 1 });
      expect(
        JSON.parse(await readFile(join(dir, "report.json"), "utf8")).findings[0],
      ).toMatchObject({
        family: "tenant-isolation",
        severity: "CRITICAL",
        confidence: "CONFIRMED",
      });
    } finally {
      if (previous === undefined) delete process.env.PERIMETER_REFERENCE_DATABASE_URL;
      else process.env.PERIMETER_REFERENCE_DATABASE_URL = previous;
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await fixture.close();
      await rm(dir, { recursive: true, force: true });
    }
  }, 60000);
});
