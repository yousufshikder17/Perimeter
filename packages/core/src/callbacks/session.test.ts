import { appendFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel } from "../target/loader.js";
import { MemoryAuditLog } from "../audit/audit-log.js";
import { SystemClock } from "../runtime/clock.js";
import { startCallbackCollector } from "./collector.js";
import { openCallbackSession } from "./session.js";

it("validates owned scratch contracts and accepts only fresh correlated, audited receipts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "perimeter-receipt-"));
  const receiptFile = join(directory, "receipts.ndjson");
  const collector = await startCallbackCollector({ receiptFile, controlPort: 0, prohibitedPort: 0 });
  try {
    const original = await loadTargetModel("examples/target.yaml");
    const objectRef = { param: "id", kind: "webhook", ownership: "user" as const };
    const target = parseTargetModel({ ...original, endpoints: [
      { id: "create", method: "POST", path: "/webhooks", creates: "webhook" },
      { id: "delete", method: "DELETE", path: "/webhooks/{id}", objectRef },
      { id: "dispatch", method: "POST", path: "/webhooks/{id}/test", objectRef,
        webhook: { identity: original.identities[0]!.ref, urlField: "url", receiptFile: "receipts.ndjson",
          controlOrigin: collector.controlOrigin, prohibitedOrigin: collector.prohibitedOrigin, iOwnBothDestinations: true, prohibitedByPolicy: true, timeoutMs: 100 } },
    ] });
    const endpoint = target.endpoints[2]!;
    for (const invalid of [{ iOwnBothDestinations: false }, { prohibitedByPolicy: false }, { identity: "unknown" },
      { prohibitedOrigin: collector.controlOrigin }, { controlOrigin: "http://user:secret@localhost" }, { body: { url: "override" } }]) {
      expect(() => parseTargetModel({ ...target, endpoints: [...target.endpoints.slice(0, 2), { ...endpoint, webhook: { ...endpoint.webhook, ...invalid } }] })).toThrow();
    }
    expect(() => parseTargetModel({ ...target, endpoints: [target.endpoints[0], endpoint] })).toThrow();
    const audit = new MemoryAuditLog();
    const controller = new AbortController();
    const options = { endpoint, targetDirectory: directory, clock: new SystemClock(), signal: controller.signal, audit, scanId: "scan", probeId: "ssrf/test" };
    const stale = { version: 1, kind: "control", token: "a".repeat(32), method: "POST", observedAt: new Date().toISOString() };
    await appendFile(receiptFile, JSON.stringify(stale) + "\n");
    const session = await openCallbackSession(options);
    expect(session.controlUrl).not.toBe((await openCallbackSession(options)).controlUrl);
    await appendFile(receiptFile, JSON.stringify({ ...stale, token: session.prohibitedUrl.split("/").pop(), kind: "prohibited", observedAt: "2000-01-01T00:00:00.000Z" }) + "\n");
    expect(await session.wait("prohibited")).toBeUndefined();
    await fetch(session.controlUrl);
    const receipt = await session.wait("control");
    expect(receipt?.direction).toBe("incoming"); expect(receipt?.ref).toBe(audit.refs()[0]);
    expect(await session.wait("control")).toBe(receipt); expect(audit.entries).toHaveLength(1);
    const waiting = session.wait("prohibited"); controller.abort(); await expect(waiting).rejects.toThrow();
    const next = await openCallbackSession({ ...options, signal: new AbortController().signal });
    await writeFile(receiptFile, ""); await expect(next.wait("control")).rejects.toThrow(/truncated/);
  } finally { await collector.stop(); await rm(directory, { recursive: true, force: true }); }
});
