import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import { CallbackReceiptSchema, startCallbackCollector } from "./collector.js";

it("collects bounded minimal receipts on two owned origins without overwriting files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-callback-"));
  const receiptFile = join(directory, "receipts.ndjson");
  const collector = await startCallbackCollector({ receiptFile, controlPort: 0, prohibitedPort: 0 });
  try {
    const path = `/perimeter-callback/${"a".repeat(32)}`;
    for (const origin of [collector.controlOrigin, collector.prohibitedOrigin]) {
      expect((await fetch(origin + path, { method: "POST", headers: { authorization: "Bearer secret" }, body: "private-body" })).status).toBe(204);
    }
    expect((await fetch(collector.controlOrigin + "/anything")).status).toBe(404);
    expect((await fetch(collector.controlOrigin + path, { method: "PUT" })).status).toBe(405);
    expect((await fetch(collector.controlOrigin + path, { method: "POST", body: "x".repeat(16385) })).status).toBe(413);
    const text = await readFile(receiptFile, "utf8");
    const receipts = text.trim().split("\n").map((line) => CallbackReceiptSchema.parse(JSON.parse(line)));
    expect(receipts.map((r) => r.kind)).toEqual(["control", "prohibited"]);
    expect(text).not.toMatch(/secret|private-body|authorization/);
    await expect(startCallbackCollector({ receiptFile, controlPort: 0, prohibitedPort: 0 })).rejects.toThrow();
    await expect(startCallbackCollector({ receiptFile: join(directory, "exposed"), host: "0.0.0.0" })).rejects.toThrow(/acknowledgement/);
    const result = await promisify(execFile)(process.execPath, [resolve("packages/cli/dist/bin.js"), "callbacks", "serve", "--out", join(directory, "cli.ndjson"),
      "--control-port", "0", "--prohibited-port", "0", "--duration-seconds", "1"]);
    expect(JSON.parse(result.stdout).controlOrigin).toMatch(/^http:\/\/127.0.0.1:/);
  } finally { await collector.stop(); await rm(directory, { recursive: true, force: true }); }
}, 10000);
