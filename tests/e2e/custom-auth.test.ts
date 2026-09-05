import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, it } from "vitest";
import { loadTargetModel } from "@perimeter/core";
import { start } from "../../apps/reference-target/dist/server.js";

it("runs CLI scans with cached custom credentials and fails closed without leaking hook errors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter custom auth # "));
  const { server, port } = await start(0);
  try {
    const target = await loadTargetModel("examples/target.yaml");
    target.baseUrl = `http://localhost:${port}`;
    target.auth = { scheme: "custom", customHook: "./credentials.mjs", refresh: { ttlSeconds: 60 } };
    const targetPath = join(directory, "target.json");
    await writeFile(targetPath, JSON.stringify(target));
    await writeFile(join(directory, "credentials.mjs"), `
      import { appendFile } from "node:fs/promises";
      export default async ({ ref, tenant }) => {
        await appendFile(new URL("./calls.txt", import.meta.url), ref + "\\n");
        return { Authorization: "Bearer " + tenant + ":secret-user" };
      }
    `);
    const configPath = join(directory, "scan.json");
    const config = {
      target: targetPath,
      include: ["tenant-isolation", "idor"],
      failOn: "none",
      output: {
        json: join(directory, "findings.json"),
        markdown: join(directory, "report.md"),
        auditLog: join(directory, "audit.ndjson"),
      },
    };
    const cli = resolve("packages/cli/dist/bin.js");
    const run = () => promisify(execFile)(process.execPath, [cli, "scan", "--config", configPath], {
      timeout: 15_000,
    });
    await writeFile(configPath, JSON.stringify(config));
    await run();
    const findings = JSON.parse(await readFile(config.output.json, "utf8")) as {
      findings: { family: string }[]; skipped: { reason: string }[];
    };
    expect(findings.findings.map((finding) => finding.family).sort()).toEqual(["idor", "tenant-isolation"]);
    expect(findings.skipped.every((skip) => skip.reason === "not in include filter")).toBe(true);
    const calls = (await readFile(join(directory, "calls.txt"), "utf8")).trim().split("\n");
    expect(calls.length).toBeGreaterThanOrEqual(2);
    expect(new Set(calls).size).toBe(calls.length);
    const audit = await readFile(config.output.auditLog, "utf8");
    expect(audit).toContain("redacted");
    expect(audit).not.toContain("Bearer tenant-a:secret-user");
    expect(audit).not.toContain("Bearer tenant-b:secret-user");

    await writeFile(join(directory, "credentials.mjs"),
      'export default async () => { throw new Error("private-credential-value"); };');
    // Both fixture-setup and probe execution must propagate authentication failure.
    for (const family of ["tenant-isolation", "injection"]) {
      config.include = [family];
      config.output.json = join(directory, `failed-${family}.json`);
      await writeFile(configPath, JSON.stringify(config));
      const error = await run().then(() => undefined, (reason: unknown) => reason) as {
        code: number; stdout: string; stderr: string;
      } | undefined;
      expect(error).toBeDefined();
      expect(error!.code).not.toBe(0);
      expect(error!.stdout + error!.stderr).toContain("Authentication hook failed");
      expect(error!.stdout + error!.stderr).not.toContain("private-credential-value");
      await expect(readFile(config.output.json)).rejects.toMatchObject({ code: "ENOENT" });
    }
  } finally {
    await new Promise<void>((resolveClose, reject) => {
      server.close((error) => error ? reject(error) : resolveClose());
      server.closeAllConnections();
    });
    await rm(directory, { recursive: true, force: true });
  }
});
