import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { parse as parseYaml } from "yaml";
import { expect, it, vi } from "vitest";
import { loadTargetModel } from "../loader.js";
import { discoverFromCrawl } from "./crawl.js";

it("crawls authenticated HTML/JSON through the CLI and enforces scope, bounds, and authorization", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-crawl-"));
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    if (req.url === "/token") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ access_token: "crawl-secret", token_type: "Bearer" }));
      return;
    }
    if (req.headers.authorization !== "Bearer crawl-secret") { res.writeHead(401); res.end(); return; }
    if (req.url === "/denied") { res.writeHead(403); res.end(); return; }
    if (req.url === "/slow") return; // Client cancellation closes this connection.
    if (req.url === "/large") { res.end("x".repeat(1024 * 1024 + 1)); return; }
    if (req.url === "/base") {
      res.setHeader("content-type", "text/html");
      res.end('<base href="/nested/"><base href="http://localhost:1/"><a href="child">relative</a>');
      return;
    }
    if (req.url === "/external-base") {
      res.setHeader("content-type", "text/html");
      res.end('<base href="http://localhost:1/"><a href="never">external</a>');
      return;
    }
    if (req.url === "/redirect") { res.writeHead(302, { location: "/last" }); res.end(); return; }
    if (req.url === "/escape") { res.writeHead(302, { location: "http://localhost:1/never" }); res.end(); return; }
    if (req.url === "/missing") { res.writeHead(404); res.end(); return; }
    if (req.url === "/api") {
      res.setHeader("content-type", "application/hal+json");
      res.end(JSON.stringify({ _links: { next: { href: "/deep" }, self: { href: "/api" } } }));
      return;
    }
    res.setHeader("content-type", "text/html");
    res.end(req.url === "/" ? `
      <a href="/api">API</a><a href="/api#again">duplicate</a>
      <a href="/redirect">redirect</a><a href="/escape">external redirect</a>
      <a href="/missing">missing</a><a href="?token=query-secret">query</a>
      <a href="http://localhost:1/never">external</a><a href="javascript:alert(1)">script</a>
      <a href="https://${req.headers.host}/never">other scheme</a>
      <a href="//user:password@${req.headers.host}/never">userinfo</a>
      <form action="/never" method="post"><button>submit</button></form>
      <img src="/never"><script src="/never"></script>private-body-secret
    ` : '<a href="/">cycle</a>');
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    const target = await loadTargetModel("examples/target.yaml");
    target.baseUrl = `http://127.0.0.1:${address.port}`;
    target.auth = { scheme: "oauth2_password", tokenEndpoint: "/token" };
    target.identities[0]!.credentials = { env: "PERIMETER_CRAWL_TEST" };
    target.authorization.rateLimit = { globalRps: 1000, perHostRps: 1000, burst: 1000 };
    vi.stubEnv("PERIMETER_CRAWL_TEST", JSON.stringify({ username: "test", password: "password-secret" }));
    const path = join(directory, "target.json");
    const auditLog = join(directory, "audit.ndjson");
    await writeFile(path, JSON.stringify(target));
    const as = target.identities[0]!.ref;
    const { stdout, stderr } = await promisify(execFile)(process.execPath, [
      resolve("packages/cli/dist/bin.js"), "model", "crawl", path, "--as", as, "--audit-log", auditLog,
    ], { timeout: 10000 });
    const draft = parseYaml(stdout) as { endpoints: Array<{ path: string; auth: string }> };
    expect(draft.endpoints.map((endpoint) => endpoint.path)).toEqual(["/", "/api", "/deep", "/last"]);
    expect(draft.endpoints.every((endpoint) => endpoint.auth === "optional")).toBe(true);
    expect(stderr).toContain("Review required");
    expect(requests).toEqual(["POST /token", "GET /", "GET /api", "GET /redirect", "GET /escape", "GET /missing", "GET /deep", "GET /last"]);
    const audit = await readFile(auditLog, "utf8");
    for (const secret of ["crawl-secret", "password-secret", "private-body-secret", "query-secret"]) expect(audit).not.toContain(secret);
    expect(audit.trim().split("\n")).toHaveLength(requests.length);

    requests.length = 0;
    const shallow = await discoverFromCrawl(path, { as, auditLog, maxDepth: 0 });
    expect(shallow.endpoints.map((endpoint) => endpoint.path)).toEqual(["/"]);
    expect(shallow.reviewNotes.join(" ")).toContain("Depth limit");
    expect(requests).toEqual(["POST /token", "GET /"]);
    const limited = await discoverFromCrawl(path, { as, auditLog, maxPages: 2 });
    expect(limited.endpoints.map((endpoint) => endpoint.path)).toEqual(["/", "/api"]);
    expect(limited.reviewNotes.join(" ")).toContain("Page limit");
    const base = await discoverFromCrawl(path, { as, auditLog, start: "/base", maxDepth: 1 });
    expect(base.endpoints.map((endpoint) => endpoint.path)).toEqual(["/base", "/nested/child"]);
    const externalBase = await discoverFromCrawl(path, { as, auditLog, start: "/external-base" });
    expect(externalBase.endpoints.map((endpoint) => endpoint.path)).toEqual(["/external-base"]);

    requests.length = 0;
    await expect(discoverFromCrawl(path, { as: "unknown", auditLog })).rejects.toThrow("identity");
    await expect(discoverFromCrawl(path, { as, auditLog, start: "http://localhost:1/" })).rejects.toThrow("target-origin");
    await expect(discoverFromCrawl(path, { as, auditLog, start: "/?token=secret" })).rejects.toThrow("target-origin");
    await expect(discoverFromCrawl(path, { as, auditLog, maxPages: 0 })).rejects.toThrow();
    await writeFile(path, JSON.stringify({ ...target, authorization: { ...target.authorization, iAmAuthorizedToTest: false } }));
    await expect(discoverFromCrawl(path, { as, auditLog })).rejects.toThrow();
    expect(requests).toEqual([]);
    vi.stubEnv("PERIMETER_CONFIRM_PRODUCTION", "no");
    await writeFile(path, JSON.stringify({ ...target, authorization: { ...target.authorization, environment: "production" } }));
    await expect(discoverFromCrawl(path, { as, auditLog })).rejects.toThrow("PERIMETER_CONFIRM_PRODUCTION");
    expect(requests).toEqual([]);
    await writeFile(path, JSON.stringify(target));
    await expect(discoverFromCrawl(path, { as, auditLog, start: "/denied" })).rejects.toThrow("access denied");
    await expect(discoverFromCrawl(path, { as, auditLog, start: "/large" })).rejects.toThrow("body limit");
    await expect(discoverFromCrawl(path, { as, auditLog, start: "/slow", maxWallClockSeconds: 1 })).rejects.toThrow();
    const controller = new AbortController();
    controller.abort();
    const count = requests.length;
    await expect(discoverFromCrawl(path, { as, auditLog }, controller.signal)).rejects.toThrow();
    expect(requests).toHaveLength(count);

    const output = join(directory, "draft.yaml");
    await writeFile(output, "keep this model");
    await expect(promisify(execFile)(process.execPath, [
      resolve("packages/cli/dist/bin.js"), "model", "crawl", path, "--as", as,
      "--max-pages", "1", "--audit-log", auditLog, "--out", output,
    ])).rejects.toThrow();
    expect(await readFile(output, "utf8")).toBe("keep this model");
  } finally {
    vi.unstubAllEnvs();
    server.closeAllConnections();
    await new Promise<void>((done) => server.close(() => done()));
    await rm(directory, { recursive: true, force: true });
  }
}, 20000);
