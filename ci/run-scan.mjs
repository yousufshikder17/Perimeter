/* global process */
import { spawn } from "node:child_process";
import { lstat, mkdir, mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, URL } from "node:url";
import { parseScanConfig, readConfigFile } from "../packages/core/dist/index.js";

// A checked-out, built Perimeter tree is required; no implicit package publishing/install.
const cli = fileURLToPath(new URL("../packages/cli/dist/bin.js", import.meta.url));
export const artifactNames = ["findings.json", "report.md", "report.html", "report.sarif", "report.junit.xml"];

export async function runCiScan(configPath, cwd = process.cwd()) {
  const outputDirectory = resolve(cwd, ".perimeter-ci");
  await mkdir(outputDirectory, { recursive: true });
  if (!(await lstat(outputDirectory)).isDirectory() || (await lstat(outputDirectory)).isSymbolicLink()) throw new Error("CI output directory must not be a link");
  const paths = [...artifactNames, "audit.ndjson"].map(name => join(outputDirectory, name));
  // Remove only our known outputs, so a failed new scan cannot publish old findings.
  // Refuse aliases/directories instead of following them or deleting recursively.
  for (const path of paths) {
    const stat = await lstat(path).catch(error => { if (error.code === "ENOENT") return null; throw error; });
    if (stat && (!stat.isFile() || stat.isSymbolicLink())) throw new Error("CI output file must be a regular file");
  }
  const resolvedConfig = resolve(cwd, configPath);
  if (paths.includes(resolvedConfig)) throw new Error("CI config must be outside reserved output paths");
  // Read the input before removing output files, but do not log its contents.
  const input = await readConfigFile(resolvedConfig).catch(() => null);
  if (input && [input.target, input.baseline, input.checkpoint].some(path => typeof path === "string" && paths.includes(resolve(cwd, path)))) throw new Error("CI inputs must be outside reserved output paths");
  for (const path of paths) await unlink(path).catch(error => { if (error.code !== "ENOENT") throw error; });
  const config = parseScanConfig(input);
  if (config.checkpoint || config.resume) throw new Error("CI templates run fresh scans; checkpoint replay is not supported");
  config.output = { json: paths[0], markdown: paths[1], html: paths[2], sarif: paths[3], junit: paths[4], auditLog: paths[5] };
  const temporary = await mkdtemp(join(tmpdir(), "perimeter-ci-config-"));
  try {
    const path = join(temporary, "scan.json");
    await writeFile(path, JSON.stringify(config), { mode: 0o600 });
    return await new Promise((done, reject) => {
      const child = spawn(process.execPath, [cli, "scan", "--config", path], { cwd, stdio: "inherit", shell: false, windowsHide: true });
      const stop = () => child.kill("SIGTERM");
      const cleanup = () => { process.removeListener("SIGINT", stop); process.removeListener("SIGTERM", stop); };
      process.once("SIGINT", stop); process.once("SIGTERM", stop);
      child.once("error", error => { cleanup(); reject(error); });
      child.once("exit", (code) => { cleanup(); done(code ?? 1); });
    });
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await runCiScan(process.env.PERIMETER_SCAN_CONFIG || "perimeter.scan.yaml"); }
  catch { process.stderr.write("Perimeter CI scan failed; verify the reviewed configuration, build, and output paths.\n"); process.exitCode = 1; }
}
