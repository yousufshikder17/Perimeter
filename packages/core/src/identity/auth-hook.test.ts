import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { TargetModel } from "@perimeter/sdk";
import { describe, expect, it } from "vitest";
import { loadTargetModel } from "../target/loader.js";
import { Orchestrator } from "../orchestrator.js";
import { parseScanConfig } from "../config/scan-config.js";

// Exercise Node's real module loader, not Vitest's transformed dynamic imports.
async function checkHook(target: TargetModel, targetPath: string): Promise<unknown> {
  const moduleUrl = pathToFileURL(resolve("packages/core/dist/identity/auth-hook.js")).href;
  const { stdout } = await promisify(execFile)(process.execPath, [
    "--input-type=module", "--eval",
    `import { loadAuthHook } from ${JSON.stringify(moduleUrl)};
     const hook = await loadAuthHook(JSON.parse(process.argv[1]), process.argv[2]);
     console.log(JSON.stringify(hook ? await hook({ref: "a", tenant: "tenant-a", role: "member"}) : null));`,
    JSON.stringify(target), targetPath,
  ], { timeout: 10_000 });
  return JSON.parse(stdout) as unknown;
}

describe("configured authentication hooks", () => {
  it("loads local default exports relative to the model and fails closed", async () => {
    const directory = await mkdtemp(join(tmpdir(), "perimeter hook # "));
    try {
      const target = await loadTargetModel("examples/target.yaml");
      target.auth = { scheme: "custom", customHook: "./credentials.mjs" };
      const targetPath = join(directory, "target.json");
      await writeFile(join(directory, "credentials.mjs"),
        'export default async ({ tenant, role }) => ({ authorization: `Bearer ${tenant}:${role}` });');
      expect(await checkHook(target, targetPath))
        .toEqual({ authorization: "Bearer tenant-a:member" });

      target.auth.customHook = "./bad.mjs";
      await writeFile(join(directory, "bad.mjs"), "export default {}; ");
      await expect(checkHook(target, targetPath)).rejects.toThrow("default-export a function");
      target.auth.customHook = "./missing.mjs";
      await expect(checkHook(target, targetPath)).rejects.toThrow("Could not load");
      target.auth.customHook = "https://example.com/hook.mjs";
      await expect(checkHook(target, targetPath)).rejects.toThrow("local filesystem path");
      delete target.auth.customHook;
      await expect(checkHook(target, targetPath)).rejects.toThrow("requires auth.customHook");
      target.auth.scheme = "bearer";
      expect(await checkHook(target, targetPath)).toBeNull();

      // Authorization must fail before operator code is imported.
      target.auth = { scheme: "custom", customHook: "./missing.mjs" };
      target.authorization.environment = "production";
      await writeFile(targetPath, JSON.stringify(target));
      const confirmation = process.env.PERIMETER_CONFIRM_PRODUCTION;
      delete process.env.PERIMETER_CONFIRM_PRODUCTION;
      try {
        await expect(new Orchestrator(parseScanConfig({ target: targetPath }), []).run())
          .rejects.toThrow("PERIMETER_CONFIRM_PRODUCTION");
      } finally {
        if (confirmation !== undefined) process.env.PERIMETER_CONFIRM_PRODUCTION = confirmation;
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
