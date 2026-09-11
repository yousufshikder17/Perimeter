import { randomBytes } from "node:crypto";
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import type { CallbackSession, Clock, Endpoint, HttpExchange } from "@perimeter/sdk";
import type { AuditSink } from "../audit/audit-log.js";
import { CallbackReceiptSchema, MAX_RECEIPT_BYTES } from "./collector.js";

export async function openCallbackSession(options: {
  endpoint: Endpoint; targetDirectory: string; clock: Clock; signal: AbortSignal;
  audit: AuditSink; scanId: string; probeId: string;
}): Promise<CallbackSession> {
  const model = options.endpoint.webhook;
  if (!model) throw new Error("Endpoint has no owned callback contract");
  options.signal.throwIfAborted();
  const path = resolve(options.targetDirectory, model.receiptFile);
  const initial = await open(path, "r");
  const baseline = await initial.stat().finally(() => initial.close());
  if (!baseline.isFile() || baseline.size > MAX_RECEIPT_BYTES) throw new Error("Callback receipt file is not a bounded regular file");
  // Security correlation tokens must be unpredictable and fresh even with a replayed scan seed.
  const tokens = { control: randomBytes(16).toString("hex"), prohibited: randomBytes(16).toString("hex") };
  const urls = { control: `${new URL(model.controlOrigin).origin}/perimeter-callback/${tokens.control}`,
    prohibited: `${new URL(model.prohibitedOrigin).origin}/perimeter-callback/${tokens.prohibited}` };
  const started = options.clock.now();
  const observed = new Map<string, HttpExchange>();
  return { controlUrl: urls.control, prohibitedUrl: urls.prohibited, async wait(kind) {
    options.signal.throwIfAborted();
    if (kind !== "control" && kind !== "prohibited") throw new Error("Unknown callback receipt kind");
    const cached = observed.get(kind);
    if (cached) return cached;
    const deadline = options.clock.now() + model.timeoutMs;
    for (;;) {
      options.signal.throwIfAborted();
      const file = await open(path, "r");
      let text: string;
      try {
        const stat = await file.stat();
        if (!stat.isFile() || stat.dev !== baseline.dev || stat.ino !== baseline.ino || stat.size < baseline.size || stat.size > MAX_RECEIPT_BYTES) {
          throw new Error("Callback receipt file changed identity, was truncated, or exceeded its limit");
        }
        // ponytail: reread the bounded tail; add incremental indexing only for high-volume collectors.
        const buffer = Buffer.alloc(stat.size - baseline.size);
        const { bytesRead } = await file.read(buffer, 0, buffer.length, baseline.size);
        if (bytesRead !== buffer.length) throw new Error("Callback receipt file changed while reading");
        text = buffer.toString("utf8");
      } finally { await file.close(); }
      const lines = text.split("\n");
      const partial = lines.pop()!;
      if (partial.length > 1024) throw new Error("Callback receipt line exceeds its limit");
      for (const line of lines) {
        if (line.length > 1024) throw new Error("Callback receipt line exceeds its limit");
        let value: unknown;
        try { value = JSON.parse(line); } catch { throw new Error("Invalid callback receipt JSON"); }
        const parsed = CallbackReceiptSchema.safeParse(value);
        if (!parsed.success) throw new Error("Invalid callback receipt");
        const receipt = parsed.data;
        const timestamp = Date.parse(receipt.observedAt);
        if (receipt.kind !== kind || receipt.token !== tokens[kind] || timestamp < started || timestamp > options.clock.now()) continue;
        const exchange: HttpExchange = { ref: "pending", direction: "incoming",
          request: { method: receipt.method, url: urls[kind], headers: {} },
          response: { status: 204, headers: { "x-perimeter-receipt-time": receipt.observedAt } } };
        const entry = await options.audit.append({ scanId: options.scanId, probeId: options.probeId, exchange });
        exchange.ref = entry.ref;
        observed.set(kind, exchange);
        return exchange;
      }
      const remaining = deadline - options.clock.now();
      if (remaining <= 0) return undefined;
      await options.clock.sleep(Math.min(200, remaining), options.signal);
    }
  } };
}
