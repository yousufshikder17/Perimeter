import { skip, type Probe, type GrpcResponse } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

export const grpcAuthorization: Probe = {
  manifest: { id: "grpc/authorization", family: "grpc", version: "0.1.0", schemaVersion: "1",
    requires: { allIdentities: true, endpoints: ["grpcUnary"] },
    safety: { class: "read-only", maxRequests: 60, destructive: false } },
  async plan(ctx) {
    const endpoints = ctx.target.endpoints.filter((e) => e.grpc && e.auth === "required");
    if (!ctx.grpc || !endpoints.length) return skip("no reviewed protected unary gRPC endpoint/transport");
    return { probeId: this.manifest.id, steps: endpoints.map((e) => ({ id: `grpc:${e.id}`, endpointId: e.id,
      description: `Compare owner, anonymous and other-identity protected data on ${e.id}`, estimatedRequests: 3 })) };
  },
  async run(plan, ctx) {
    if (!ctx.grpc) return;
    for (const step of plan.steps) {
      if (ctx.signal.aborted || ctx.budget.remaining < 3) { ctx.logger.warn("gRPC checks incomplete: control budget or cancellation"); return; }
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.grpc) continue;
      const model = endpoint.grpc;
      const fixture = endpoint.objectRef ? ctx.fixtures.owned(endpoint.objectRef.kind, model.ownerIdentity) : undefined;
      if (endpoint.objectRef && !fixture) { ctx.logger.warn("gRPC check omitted: no owner scratch fixture", { endpoint: endpoint.id }); continue; }
      const request = { endpointId: endpoint.id, ...(fixture ? { scratchObjectId: fixture.id } : {}) };
      const owner = await ctx.grpc.request({ ...request, as: model.ownerIdentity });
      const baseline = marker(owner, model.resultPath);
      if (baseline === undefined || (fixture && String(baseline) !== fixture.id)) {
        ctx.logger.warn("gRPC check inconclusive: owner lacks captured protected scalar", { endpoint: endpoint.id }); continue;
      }
      for (const [mode, as] of [["anonymous", undefined], ["other-identity", model.otherIdentity]] as const) {
        const response = await ctx.grpc.request({ ...request, ...(as ? { as } : {}) });
        if (marker(response, model.resultPath) === baseline) {
          ctx.report(buildFinding({ probeId: this.manifest.id, family: "grpc", title: `Protected gRPC data served to ${mode} on ${endpoint.id}`,
            severity: "HIGH", confidence: "FIRM", cwe: [as ? "CWE-639" : "CWE-306"],
            target: { endpointId: endpoint.id, method: "GRPC", path: endpoint.path, tenantScoped: endpoint.tenantScoped },
            affectedIdentities: as ? [model.ownerIdentity, as] : [model.ownerIdentity], locator: `${mode}:${JSON.stringify(model.resultPath)}`,
            evidence: { summary: `A successful owner control and ${mode} returned the same reviewed protected scalar. Review the field's authorization semantics before confirming impact.`,
              exchanges: [owner.exchange, response.exchange], auditRefs: [owner.exchange.ref, response.exchange.ref],
              differential: { baseline: owner.exchange.ref, probe: response.exchange.ref, diff: `The protected scalar remained visible to ${mode}.` },
              reproduction: { seed: "see scan config", steps: ["Execute the exact modeled unary call as the owner and capture its protected scalar.",
                `Repeat the identical request as ${as ?? "anonymous"}; compare captured decoded data, not HTTP status.`] } },
            remediation: { guidance: "Authenticate gRPC metadata and authorize each RPC, object and returned field using the verified principal and tenant. Do not rely on transport-level authentication alone.",
              references: ["https://grpc.io/docs/guides/auth/"], effort: "moderate" } }));
        } else if ([7, 16].includes(response.code)) {
          ctx.report({ kind: "pass", probeId: this.manifest.id, family: "grpc", endpointId: endpoint.id,
            title: `gRPC ${mode} denied on ${endpoint.id}`, summary: "Owner control succeeded; comparison returned PERMISSION_DENIED or UNAUTHENTICATED." });
        } else ctx.logger.warn("gRPC comparison inconclusive: neither matching data nor explicit auth denial", { endpoint: endpoint.id, mode });
      }
    }
  },
};

function marker(response: GrpcResponse, path: string[]): string | number | undefined {
  if (response.code !== 0) return undefined;
  try {
    let value: unknown = JSON.parse(response.exchange.response.body ?? "");
    for (const key of path) value = value !== null && typeof value === "object" && Object.hasOwn(value, key)
      ? (value as Record<string, unknown>)[key] : undefined;
    return typeof value === "string" && value.trim() && !value.includes("«redacted»") ? value :
      typeof value === "number" && Number.isFinite(value) ? value : undefined;
  } catch { return undefined; }
}
