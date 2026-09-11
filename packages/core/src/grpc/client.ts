import { Client, Metadata, credentials, status, type ClientUnaryCall } from "@grpc/grpc-js";
import { GrpcRequestSchema, parseTargetModel, type GrpcRequest, type GrpcResponse, type GuardedGrpcClient, type FixtureView, type HttpExchange, type Identity, type TargetModel } from "@perimeter/sdk";
import type { AuditSink } from "../audit/audit-log.js";
import { redactBody, redactHeaders } from "../audit/redaction.js";
import type { MutableBudget } from "../runtime/budget.js";
import type { RateLimiter } from "../safety/rate-limiter.js";
import { SafetyViolation } from "../safety/guard.js";
import { inspectOutboundPayload } from "../safety/outbound-inspector.js";
import { compileGrpc } from "./codec.js";

export interface GrpcClientDeps {
  target: TargetModel;
  probeId: string;
  scanId: string;
  budget: MutableBudget;
  limiter: RateLimiter;
  audit: AuditSink;
  resolveIdentity: (ref: string) => Identity;
  fixtures: FixtureView;
  signal: AbortSignal;
  captureBodies?: boolean;
  maxResponseBytes?: number;
}

/** Exact modeled calls only; credentials and protobuf bytes never reach workers. */
export class GuardedGrpcClientImpl implements GuardedGrpcClient {
  readonly #target: TargetModel;
  constructor(private readonly deps: GrpcClientDeps) {
    this.#target = parseTargetModel(structuredClone(deps.target));
  }

  async request(input: GrpcRequest, requestSignal?: AbortSignal): Promise<GrpcResponse> {
    const req = GrpcRequestSchema.parse(input);
    const d = this.deps;
    const signal = requestSignal ? AbortSignal.any([d.signal, requestSignal]) : d.signal;
    signal.throwIfAborted();
    const endpoint = this.#target.endpoints.find((e) => e.id === req.endpointId);
    if (!endpoint?.grpc || !endpoint.grpc.readOnly) throw new SafetyViolation("unreviewed gRPC method");
    if (req.as && !this.#target.identities.some((i) => i.ref === req.as)) throw new SafetyViolation("unknown gRPC identity");
    const model = endpoint.grpc;
    const body = { ...model.request };
    if (endpoint.objectRef) {
      const fixture = d.fixtures.owned(endpoint.objectRef.kind, model.ownerIdentity);
      if (!fixture || fixture.id !== req.scratchObjectId) throw new SafetyViolation("gRPC object reference requires the owner's engine-created scratch ID");
      body[endpoint.objectRef.param] = fixture.id;
    } else if (req.scratchObjectId) throw new SafetyViolation("gRPC endpoint has no scratch parameter");
    const text = JSON.stringify(body);
    if (Buffer.byteLength(text) > 16384 || !inspectOutboundPayload([text]).ok) throw new SafetyViolation("gRPC payload policy");
    const codec = compileGrpc(endpoint);
    const bytes = codec.encode(body);
    const origin = new URL(model.origin ?? this.#target.baseUrl);
    d.budget.consume(); await d.budget.checkpoint();
    await d.limiter.acquire(origin.host, signal);
    const identity = req.as ? d.resolveIdentity(req.as) : undefined;
    const headers = identity ? await identity.headers() : {};
    signal.throwIfAborted();
    const metadata = new Metadata();
    for (const [key, value] of Object.entries(headers)) metadata.set(key, value);
    const secrets = Object.values(headers).flatMap((value) => [value, value.replace(/^Bearer\s+/i, "")]).filter(Boolean);
    const scrub = (value: string) => secrets.reduce((result, secret) => result.replaceAll(secret, "«redacted»"), value);
    const limit = Math.min(16384, d.maxResponseBytes ?? 16384);
    if (!Number.isSafeInteger(limit) || limit <= 0) throw new Error("Invalid gRPC response ceiling");
    const client = new Client(origin.host, origin.protocol === "https:" ? credentials.createSsl() : credentials.createInsecure(), {
      "grpc.enable_retries": 0, "grpc.enable_http_proxy": 0,
      "grpc.max_send_message_length": 16384, "grpc.max_receive_message_length": limit,
    });
    const started = Date.now();
    let code: number = status.INTERNAL;
    let value: Record<string, unknown> | undefined;
    try {
      const result = await new Promise<{ code: number; value?: Record<string, unknown> }>((resolve) => {
        let call: ClientUnaryCall | undefined;
        const abort = () => call?.cancel();
        signal.addEventListener("abort", abort, { once: true });
        try {
          call = client.makeUnaryRequest(endpoint.path, (payload: Buffer) => payload, (reply: Buffer) => codec.decode(reply),
            bytes, metadata, { deadline: Date.now() + model.deadlineMs }, (error, reply) => {
              signal.removeEventListener("abort", abort);
              resolve({ code: error?.code ?? status.OK, ...(reply ? { value: reply } : {}) });
            });
          if (signal.aborted) abort();
        } catch { signal.removeEventListener("abort", abort); resolve({ code: status.INTERNAL }); }
      });
      code = result.code; value = result.value;
    } finally { client.close(); }
    const captured = value ? JSON.stringify(value) : undefined;
    const exchange: HttpExchange = {
      ref: "pending", protocol: "grpc",
      request: { method: "GRPC", url: `${origin.origin}${endpoint.path}`, headers: redactHeaders(headers),
        body: d.captureBodies === false ? "«redacted»" : redactBody(scrub(text))! },
      response: { status: code, headers: { "content-type": "application/grpc", "grpc-status": String(code) },
        ...(captured !== undefined ? { body: d.captureBodies === false ? "«redacted»" : redactBody(scrub(captured))! } : {}),
        elapsedMs: Date.now() - started }, ...(req.as ? { issuedAs: req.as } : {}),
    };
    const entry = await d.audit.append({ scanId: d.scanId, probeId: d.probeId, exchange,
      ...(identity ? { identityRef: identity.ref, tenant: identity.tenant } : {}) });
    exchange.ref = entry.ref;
    signal.throwIfAborted();
    return { code, exchange };
  }
}
