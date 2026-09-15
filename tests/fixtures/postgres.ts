import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { setTimeout } from "node:timers/promises";
import type pgType from "../../apps/reference-target/node_modules/@types/pg/index.js";

const require = createRequire(new URL("../../apps/reference-target/package.json", import.meta.url));
export const pg = require("pg") as typeof pgType;
export const postgresEnabled = process.env.PERIMETER_TEST_POSTGRES === "1";

/** New disposable cluster, loopback-only port, no volumes. No existing database is touched. */
export async function postgresFixture() {
  const name = "perimeter-pg-" + randomUUID();
  const password = randomUUID();
  const docker = (...args: string[]) =>
    execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  docker(
    "run",
    "--detach",
    "--rm",
    "--name",
    name,
    "-p",
    "127.0.0.1::5432",
    "-e",
    "POSTGRES_PASSWORD=" + password,
    "postgres:17-alpine",
  );
  let admin: InstanceType<typeof pg.Client> | undefined;
  try {
    const port = docker("port", name, "5432/tcp").split(":").at(-1);
    const adminUrl = "postgresql://postgres:" + password + "@127.0.0.1:" + port + "/postgres";
    for (let n = 0; n < 100; n++) {
      const candidate = new pg.Client({
        connectionString: adminUrl,
        connectionTimeoutMillis: 1000,
      });
      try {
        await candidate.connect();
        admin = candidate;
        break;
      } catch {
        await candidate.end().catch(() => {});
        await setTimeout(100);
      }
    }
    if (!admin) throw new Error("Disposable PostgreSQL did not become ready");
    await admin.query(
      await readFile(new URL("../../apps/reference-target/db/schema.sql", import.meta.url), "utf8"),
    );
    // UUID is generated locally, never operator input. PostgreSQL passwords cannot be bind parameters.
    await admin.query("ALTER ROLE perimeter_reference PASSWORD '" + password + "'");
    const appUrl = adminUrl.replace("postgres:", "perimeter_reference:");
    return {
      admin,
      adminUrl,
      appUrl,
      async close() {
        await admin!.end();
        docker("stop", name);
      },
    };
  } catch (error) {
    await admin?.end().catch(() => {});
    docker("stop", name);
    throw error;
  }
}
