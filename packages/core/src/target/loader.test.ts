import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { stringify } from "smol-toml";
import { expect, it } from "vitest";
import { loadTargetModel } from "./loader.js";

it("loads TOML targets and CLI scan configs with the same validation as YAML", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-toml-"));
  try {
    const target = await loadTargetModel("examples/target.yaml");
    const path = join(directory, "target.TOML");
    await writeFile(path, stringify(target));
    expect(await loadTargetModel(path)).toEqual(target);
    const output = { json: join(directory, "findings.json"), markdown: join(directory, "report.md"), auditLog: join(directory, "audit.ndjson") };
    const config = join(directory, "scan.toml");
    await writeFile(config, stringify({ target: path, include: ["no-probes-selected"], output }));
    await promisify(execFile)(process.execPath, [resolve("packages/cli/dist/bin.js"), "scan", "--config", config], { timeout: 10000 });
    expect(JSON.parse(await readFile(output.json, "utf8"))).toMatchObject({ findings: [] });
    await writeFile(path, 'name = "one"\nname = "two"');
    await expect(loadTargetModel(path)).rejects.toThrow();
    await writeFile(path, 'name = "missing authorization"');
    await expect(loadTargetModel(path)).rejects.toThrow();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
