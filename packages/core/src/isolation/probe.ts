import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import { ulid } from "ulid";
import type { HttpExchange, Probe, ProbeContext } from "@perimeter/sdk";
import { AuthenticationError } from "../identity/identity-manager.js";
import { computeFingerprint } from "../findings/fingerprint.js";
import { IsolatedProbeSchema, ISOLATED_PROTOCOL_VERSION, MAX_WORKER_FRAME_BYTES, MAX_WORKER_OUTPUT_BYTES, WorkerMessageSchema, type IsolatedProbeConfig } from "./protocol.js";

export class IsolatedProbeError extends Error {}
const managedWorkers = new WeakSet<Probe>();
export const isManagedIsolatedProbe = (probe: Probe): boolean => managedWorkers.has(probe);

/** Pure adapter: worker code is never imported or executed while loading the manifest. */
export function createIsolatedProbe(input: unknown): Probe {
  const config = IsolatedProbeSchema.parse(input);
  const probe: Probe = {
    manifest: { ...config.manifest, isolation: "subprocess" },
    async plan() {
      return { probeId: config.manifest.id, steps: [{ id: "worker", description: "Run isolated protocol v1 worker", estimatedRequests: config.manifest.safety.maxRequests }] };
    },
    async run(_plan, ctx) { await runWorker(config, ctx); },
  };
  managedWorkers.add(probe);
  return probe;
}

/** Fixed restrictions; arbitrary runtime flags, host mounts, sockets, and env forwarding are not supported. */
export function containerCreateArgs(name: string, runner: Extract<IsolatedProbeConfig["runner"], { kind: "container" }>): string[] {
  return ["create", "--name", name, "--label", "perimeter.worker=1", "--interactive", "--pull=never",
    "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
    "--user=65532:65532", "--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--cpus=1",
    "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m", "--no-healthcheck", "--log-driver=none",
    runner.image, ...runner.command];
}

async function runWorker(config: IsolatedProbeConfig, ctx: ProbeContext): Promise<void> {
  const controller = new AbortController();
  const signal = AbortSignal.any([ctx.signal, controller.signal, AbortSignal.timeout(config.timeoutSeconds * 1000)]);
  signal.throwIfAborted();
  const name = `perimeter-${randomUUID()}`;
  const runner = config.runner;
  let failure: Error | undefined;
  try {
    if (runner.kind === "container") {
      // Create first, then attach: an interrupted creation cannot leave a running worker.
      await promisify(execFile)(runner.runtime, containerCreateArgs(name, runner), { signal, timeout: config.timeoutSeconds * 1000, maxBuffer: 65536, windowsHide: true });
    } else {
      ctx.logger.warn("external command runner: operator-managed security; not a Perimeter sandbox", { probe: config.manifest.id });
    }
    const [command, ...args] = runner.kind === "container"
      ? [runner.runtime, "start", "--attach", "--interactive", name] : runner.command;
    // The Docker CLI needs its own host configuration. Plain workers receive only OS bootstrap variables, not credentials.
    const env = runner.kind === "container" ? process.env : Object.fromEntries(Object.entries(process.env)
      .filter(([key]) => ["PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"].includes(key.toUpperCase())));
    const child = spawn(command!, args, { stdio: ["pipe", "pipe", "pipe"], shell: false, windowsHide: true, env });
    const exited = new Promise<number | null>((resolve, reject) => {
      child.once("error", () => reject(new IsolatedProbeError("Worker could not start")));
      child.once("close", (code) => resolve(code));
    });
    // Attach a rejection handler immediately, including failures before stdout is read.
    void exited.catch(() => {});
    const stop = () => { child.kill("SIGKILL"); child.stdin.destroy(); child.stdout.destroy(); };
    signal.addEventListener("abort", stop, { once: true });
    let stderrBytes = 0;
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 65536) controller.abort();
    });
    child.stdin.on("error", () => controller.abort());
    try {
      signal.throwIfAborted();
      const allowedIdentities = new Set(config.manifest.requires.allIdentities
        ? ctx.target.identities.map((identity) => identity.ref) : config.manifest.requires.identities ?? []);
      const fixtures = [...new Set(ctx.target.endpoints.map((endpoint) => endpoint.creates).filter((kind): kind is string => !!kind))]
        .flatMap((kind) => ctx.fixtures.ofKind(kind)).filter((fixture) => allowedIdentities.has(fixture.ownerIdentity));
      const start = {
        type: "start", version: ISOLATED_PROTOCOL_VERSION, probeId: config.manifest.id,
        seed: String(ctx.rng.int(0, 0x100000000)),
        target: { name: ctx.target.name, baseUrl: ctx.target.baseUrl, tenancy: ctx.target.tenancy,
          endpoints: ctx.target.endpoints.map((endpoint) => Object.fromEntries(Object.entries(endpoint).filter(([key]) => key !== "fixture"))),
          identities: ctx.target.identities.filter((identity) => allowedIdentities.has(identity.ref))
            .map(({ ref, tenant, role }) => ({ ref, tenant, role })),
        },
        fixtures, budget: { limit: ctx.budget.limit, remaining: ctx.budget.remaining },
      };
      const send = async (value: unknown) => {
        const frame = JSON.stringify(value) + "\n";
        if (Buffer.byteLength(frame) > MAX_WORKER_FRAME_BYTES) throw new IsolatedProbeError("Worker input frame is too large");
        await new Promise<void>((resolve, reject) => child.stdin.write(frame, (error) => error ? reject(error) : resolve()));
      };
      await send(start);
      const exchanges = new Map<string, HttpExchange>();
      let done = false;
      let lastRequestId = -1;
      let messages = 0;
      let reports = 0;
      let totalBytes = 0;
      let buffer = Buffer.alloc(0);
      for await (const chunk of child.stdout) {
        signal.throwIfAborted();
        totalBytes += chunk.length;
        if (totalBytes > MAX_WORKER_OUTPUT_BYTES) throw new IsolatedProbeError("Worker output limit exceeded");
        buffer = Buffer.concat([buffer, chunk]);
        let newline: number;
        while ((newline = buffer.indexOf(10)) !== -1) {
          if (newline > MAX_WORKER_FRAME_BYTES || done || ++messages > 10000) throw new IsolatedProbeError("Invalid worker framing or message limit");
          const message = WorkerMessageSchema.parse(JSON.parse(buffer.subarray(0, newline).toString("utf8")));
          buffer = buffer.subarray(newline + 1);
          if (message.type === "done") { done = true; child.stdin.end(); continue; }
          if (message.type === "grpc-request") {
            if (message.id <= lastRequestId) throw new IsolatedProbeError("Worker request IDs must increase");
            lastRequestId = message.id;
            if (message.request.as && !allowedIdentities.has(message.request.as)) throw new IsolatedProbeError("Worker requested an undeclared identity");
            try {
              if (!ctx.grpc) throw new IsolatedProbeError("No guarded RPC transport");
              const response = await ctx.grpc.request(message.request, signal);
              exchanges.set(response.exchange.ref, response.exchange);
              await send({ type: "response", id: message.id, ok: true, code: response.code, exchange: response.exchange, remaining: ctx.budget.remaining });
            } catch (error) {
              if (error instanceof AuthenticationError) throw error;
              signal.throwIfAborted();
              await send({ type: "response", id: message.id, ok: false, error: "Request denied or failed", remaining: ctx.budget.remaining });
            }
            continue;
          }
          if (message.type === "request") {
            if (message.id <= lastRequestId) throw new IsolatedProbeError("Worker request IDs must increase");
            lastRequestId = message.id;
            if (message.request.as && !allowedIdentities.has(message.request.as)) throw new IsolatedProbeError("Worker requested an undeclared identity");
            const allowedHeaders = new Set(["accept", "content-type"]);
            const discriminator = ctx.target.tenancy.discriminator;
            if (discriminator.location === "header" && !/^(host|authorization|cookie|proxy-|forwarded|x-forwarded|connection|content-length|transfer-encoding)/i.test(discriminator.name)) {
              allowedHeaders.add(discriminator.name.toLowerCase());
            }
            if (Object.keys(message.request.headers ?? {}).some((header) => !allowedHeaders.has(header.toLowerCase()))) {
              throw new IsolatedProbeError("Worker requested an unsupported header");
            }
            try {
              const request = message.request;
              const response = await ctx.http.request({ method: request.method, url: request.url, signal, maxResponseBytes: 1024 * 1024,
                ...(request.as !== undefined ? { as: request.as } : {}),
                ...(request.headers !== undefined ? { headers: request.headers } : {}),
                ...(request.jwtVariant !== undefined ? { jwtVariant: request.jwtVariant } : {}),
              });
              exchanges.set(response.exchange.ref, response.exchange);
              await send({ type: "response", id: message.id, ok: true, exchange: response.exchange, remaining: ctx.budget.remaining });
            } catch (error) {
              if (error instanceof AuthenticationError) throw error;
              signal.throwIfAborted();
              await send({ type: "response", id: message.id, ok: false, error: "Request denied or failed", remaining: ctx.budget.remaining });
            }
            continue;
          }
          const endpoint = ctx.target.endpoints.find((candidate) => candidate.id === message.endpointId);
          if (!endpoint || ++reports > 100 || !exchanges.size) throw new IsolatedProbeError("Worker report has no modeled endpoint or observed traffic");
          if (message.type === "pass") {
            ctx.report({ kind: "pass", probeId: config.manifest.id, family: config.manifest.family,
              endpointId: endpoint.id, title: message.title, summary: message.summary });
          } else {
            const evidence = message.exchangeRefs.map((ref) => {
              const exchange = exchanges.get(ref);
              if (!exchange) throw new IsolatedProbeError("Worker referenced unobserved evidence");
              return exchange;
            });
            const timestamp = new Date().toISOString();
            ctx.report({ id: ulid(), schemaVersion: "1.0", probeId: config.manifest.id, family: config.manifest.family,
              fingerprint: computeFingerprint({ probeId: config.manifest.id, endpointId: endpoint.id, family: config.manifest.family, locator: message.locator }),
              title: message.title, severity: message.severity, confidence: message.confidence,
              target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path },
              affectedIdentities: [...new Set(evidence.map((exchange) => exchange.issuedAs).filter((ref): ref is string => !!ref))],
              evidence: { summary: message.summary, exchanges: evidence, auditRefs: evidence.map((exchange) => exchange.ref),
                reproduction: { seed: "see scan config", steps: [`Run isolated probe ${config.manifest.id} with the same Target Model and seed; inspect the attached exchanges.`] } },
              remediation: message.remediation, status: "open", firstSeen: timestamp, lastSeen: timestamp,
            });
          }
        }
        if (buffer.length > MAX_WORKER_FRAME_BYTES) throw new IsolatedProbeError("Worker frame limit exceeded");
      }
      const code = await exited;
      signal.throwIfAborted();
      if (!done || buffer.length || code !== 0) throw new IsolatedProbeError("Worker exited without a successful protocol completion");
    } finally {
      stop();
      signal.removeEventListener("abort", stop);
    }
  } catch (error) {
    // Worker/OS errors can contain target data. Never persist their arbitrary text.
    failure = error instanceof AuthenticationError ? error
      : new IsolatedProbeError(`Isolated probe ${config.manifest.id} failed, timed out, or violated protocol v1`);
  } finally {
    if (runner.kind === "container") {
      try {
        await promisify(execFile)(runner.runtime, ["rm", "--force", "--volumes", name], { timeout: 5000, maxBuffer: 65536, windowsHide: true });
      } catch { failure = new IsolatedProbeError(`Container cleanup could not be confirmed; inspect ${name} with the configured runtime`); }
    }
  }
  if (failure) throw failure;
}
