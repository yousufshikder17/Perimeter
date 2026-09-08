import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { loadTargetModel } from "../target/loader.js";
import { Orchestrator } from "../orchestrator.js";
import { parseScanConfig } from "../config/scan-config.js";
import { ConsoleLogger } from "../runtime/logger.js";
import { createIsolatedProbe, containerCreateArgs, IsolatedProbeError } from "./probe.js";
import { IsolatedProbeSchema } from "./protocol.js";

const manifest = { id: "test/external", family: "test", version: "1", schemaVersion: "1", requires: { identities: ["tenantA.user"] },
  safety: { class: "read-only", maxRequests: 1, destructive: false } };

it("validates explicit runner security and fixes container restrictions without shell interpolation", () => {
  expect(() => IsolatedProbeSchema.parse({ manifest, runner: { kind: "command", command: ["node"] } })).toThrow();
  expect(() => IsolatedProbeSchema.parse({ manifest, runner: { kind: "container", image: "--privileged" } })).toThrow();
  expect(() => IsolatedProbeSchema.parse({ manifest: { ...manifest, safety: { ...manifest.safety, class: "mutating" } }, runner: { kind: "container", image: "worker" } })).toThrow();
  const runner = IsolatedProbeSchema.parse({ manifest, runner: { kind: "container", runtime: "podman", image: "worker:v1" } }).runner;
  if (runner.kind !== "container") throw new Error("Wrong runner");
  const args = containerCreateArgs("perimeter-test", runner);
  for (const restriction of ["--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65532:65532", "--pull=never", "--memory=256m", "--pids-limit=64"]) expect(args).toContain(restriction);
  expect(args).not.toContain("--privileged");
  expect(args).not.toContain("--volume");
});

it("runs portable workers through real guarded HTTP and fails closed on worker violations", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-isolation-"));
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    if (req.url === "/slow") return;
    if (req.url === "/large") { res.end("x".repeat(1024 * 1024 + 1)); return; }
    expect(req.headers.authorization).toBe("Bearer isolation-secret-token");
    res.setHeader("x-reflected-token", "isolation-secret-token");
    res.end('{"token":"isolation-secret-token"}');
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  vi.stubEnv("PERIMETER_ISOLATION_TEST_SECRET", "isolation-secret-token");
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    const target = await loadTargetModel("examples/target.yaml");
    target.baseUrl = `http://127.0.0.1:${address.port}`;
    target.auth = { scheme: "bearer" };
    target.identities = [{ ref: "tenantA.user", tenant: "tenant-a", role: "member", credentials: { env: "PERIMETER_ISOLATION_TEST_SECRET" } }];
    target.endpoints = [{ id: "profile", path: "/profile", method: "GET", auth: "required", tenantScoped: false, rateSensitive: false }];
    target.authorization.rateLimit = { globalRps: 1000, perHostRps: 1000, burst: 1000 };
    const path = join(directory, "target.json");
    const auditLog = join(directory, "audit.ndjson");
    await writeFile(path, JSON.stringify(target));
    const workerConfig = (mode: string) => ({ manifest, timeoutSeconds: mode === "slow" || mode === "hang" ? 1 : 5,
      runner: { kind: "command", command: [process.execPath, resolve("tests/fixtures/isolated-worker.mjs"), mode], acknowledgeExternalSecurity: true } });
    const run = (mode: string) => new Orchestrator(parseScanConfig({ target: path, output: { auditLog } }),
      [createIsolatedProbe(workerConfig(mode))], { logger: new ConsoleLogger("error") }).run();
    const success = await run("ok");
    await expect(new Orchestrator(parseScanConfig({ target: path, output: { auditLog } }),
      [{ ...createIsolatedProbe(workerConfig("ok")) }], { logger: new ConsoleLogger("error") }).run()).rejects.toThrow("declarative isolatedProbes");
    expect(success.findings).toHaveLength(1);
    expect(success.findings[0]!.affectedIdentities).toEqual(["tenantA.user"]);
    expect(success.findings[0]!.evidence.exchanges[0]!.request.headers.authorization).toBe("«redacted»");
    expect(success.skipped).toEqual([]);
    requests = 0;
    await run("budget");
    expect(requests).toBe(1);
    requests = 0;
    expect((await run("offhost")).findings).toEqual([]);
    expect(requests).toBe(0);
    expect((await run("large")).findings).toEqual([]);
    for (const mode of ["identity", "header", "write", "crash", "hang", "flood", "bad-frame", "slow", "fake-evidence"]) {
      await expect(run(mode)).rejects.toThrow(IsolatedProbeError);
    }
    const configPath = join(directory, "scan.json");
    await writeFile(configPath, JSON.stringify({ target: path, include: [manifest.id], isolatedProbes: [workerConfig("ok")], failOn: "none",
      output: { auditLog, json: join(directory, "findings.json"), markdown: join(directory, "report.md") } }));
    await promisify(execFile)(process.execPath, [resolve("packages/cli/dist/bin.js"), "scan", "--config", configPath], { timeout: 10000 });
    const artifact = await readFile(join(directory, "findings.json"), "utf8");
    expect(JSON.parse(artifact).findings).toHaveLength(1);
    expect(artifact).not.toContain("isolation-secret-token");
    expect(await readFile(auditLog, "utf8")).not.toContain("isolation-secret-token");
  } finally {
    vi.unstubAllEnvs();
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 30000);

it.runIf(process.env.PERIMETER_TEST_DOCKER === "1")("runs the prebuilt diagnostic image in the live container profile", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-container-"));
  const server = createServer((_req, res) => { res.end('{}'); });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    const target = await loadTargetModel("examples/target.yaml");
    target.baseUrl = `http://127.0.0.1:${address.port}`;
    target.endpoints = [{ id: "profile", path: "/profile", method: "GET", auth: "none", tenantScoped: false, rateSensitive: false }];
    const path = join(directory, "target.json");
    await writeFile(path, JSON.stringify(target));
    const probe = createIsolatedProbe({ manifest: { ...manifest, requires: {} },
      runner: { kind: "container", image: "perimeter-worker:local" }, timeoutSeconds: 20 });
    const result = await new Orchestrator(parseScanConfig({ target: path, output: { auditLog: join(directory, "audit.ndjson") } }),
      [probe], { logger: new ConsoleLogger("error") }).run();
    expect(result.passes).toHaveLength(1);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 30000);
