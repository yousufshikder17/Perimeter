import { createServer, type Server } from "node:http";
import { open } from "node:fs/promises";
import { z } from "zod";

export const CallbackReceiptSchema = z.object({
  version: z.literal(1), kind: z.enum(["control", "prohibited"]),
  token: z.string().regex(/^[a-f0-9]{32}$/), observedAt: z.string().datetime(),
  method: z.enum(["GET", "HEAD", "POST"]),
}).strict();
export const MAX_RECEIPT_BYTES = 1024 * 1024;

/** Operator-owned sink: no forwarding, payload retention, or target credentials. */
export async function startCallbackCollector(options: {
  receiptFile: string; host?: string; controlPort?: number; prohibitedPort?: number; acknowledgeExposure?: boolean;
}) {
  const host = options.host ?? "127.0.0.1";
  if (!["127.0.0.1", "::1"].includes(host) && options.acknowledgeExposure !== true) throw new Error("Non-loopback binding requires explicit exposure acknowledgement");
  const ports = [options.controlPort ?? 9001, options.prohibitedPort ?? 9002];
  if (ports.some((port) => !Number.isInteger(port) || port < 0 || port > 65535) || (ports[0] !== 0 && ports[0] === ports[1])) throw new Error("Two distinct valid collector ports are required");
  const file = await open(options.receiptFile, "wx", 0o600);
  const servers: Server[] = [];
  let bytes = 0;
  let writes = Promise.resolve();
  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    await Promise.all(servers.map((server) => new Promise<void>((resolve) => { server.close(() => resolve()); server.closeAllConnections(); })));
    await writes;
    await file.close();
  };
  try {
    const origins: string[] = [];
    for (const [index, kind] of (["control", "prohibited"] as const).entries()) {
      const server = createServer({ maxHeaderSize: 8192, headersTimeout: 5000, requestTimeout: 5000 }, (request, response) => {
        const token = /^\/perimeter-callback\/([a-f0-9]{32})$/.exec(request.url ?? "")?.[1];
        if (!token || !["GET", "HEAD", "POST"].includes(request.method ?? "")) {
          request.resume(); response.writeHead(token ? 405 : 404).end(); return;
        }
        let size = 0;
        request.on("error", () => { response.destroy(); });
        request.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 16384 && !response.writableEnded) response.writeHead(413, { connection: "close" }).end();
        });
        request.on("end", () => {
          if (size > 16384 || stopped) { if (!response.writableEnded) response.writeHead(503).end(); return; }
          const line = JSON.stringify({ version: 1, kind, token, observedAt: new Date().toISOString(), method: request.method }) + "\n";
          if (bytes + Buffer.byteLength(line) > MAX_RECEIPT_BYTES) { response.writeHead(503).end(); return; }
          bytes += Buffer.byteLength(line);
          writes = writes.then(async () => { await file.appendFile(line); response.writeHead(204).end(); })
            .catch(() => { bytes = MAX_RECEIPT_BYTES; response.writeHead(503).end(); });
        });
      });
      server.maxConnections = 32;
      server.setTimeout(5000, (socket) => socket.destroy());
      servers.push(server);
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(ports[index], host, () => { server.removeListener("error", reject); resolve(); }); });
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Collector did not bind a TCP address");
      origins.push(`http://${host.includes(":") ? `[${host}]` : host}:${address.port}`);
    }
    return { controlOrigin: origins[0]!, prohibitedOrigin: origins[1]!, stop };
  } catch (error) { await stop(); throw error; }
}
