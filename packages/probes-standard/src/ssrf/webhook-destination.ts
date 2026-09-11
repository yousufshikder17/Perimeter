import { scratchPath, skip, type GuardedResponse, type Probe } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";

export const webhookDestination: Probe = {
  manifest: {
    id: "ssrf/webhook-destination", family: "ssrf", version: "0.1.0", schemaVersion: "1",
    requires: { allIdentities: true, endpoints: ["webhookCallback"] },
    safety: { class: "mutating", maxRequests: 40, destructive: false },
  },
  async plan(ctx) {
    const endpoints = ctx.target.endpoints.filter((e) => e.webhook);
    if (!ctx.callbacks || !endpoints.length) return skip("no engine-owned callback capability or reviewed webhook contract");
    return { probeId: this.manifest.id, steps: endpoints.map((e) => ({ id: `webhook:${e.id}`, endpointId: e.id,
      description: "Compare observed allowed and policy-forbidden callbacks on a scratch webhook", estimatedRequests: 2 })) };
  },
  async run(plan, ctx) {
    const cleanupHeadroom = [...new Set(ctx.target.endpoints.map((e) => e.creates).filter((kind): kind is string => !!kind))]
      .reduce((count, kind) => count + ctx.fixtures.ofKind(kind).length, 0);
    for (const step of plan.steps) {
      if (ctx.signal.aborted || ctx.budget.remaining < 2 + cleanupHeadroom) {
        ctx.logger.warn("Webhook checks incomplete: insufficient budget or cancellation"); return;
      }
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.webhook || !endpoint.objectRef || !ctx.callbacks) continue;
      const model = endpoint.webhook;
      const fixture = ctx.fixtures.owned(endpoint.objectRef.kind, model.identity);
      const path = fixture && scratchPath(endpoint, fixture.id);
      if (!fixture || !path) { ctx.logger.warn("Webhook check omitted: missing owner scratch fixture"); continue; }
      const callbacks = await ctx.callbacks.open(endpoint.id);
      const dispatch = (url: string) => ctx.http.request({ method: endpoint.method, url: path, as: model.identity,
        targetsScratchObjectId: fixture.id, headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...model.body, [model.urlField]: url }), maxResponseBytes: 16384 });
      const control = await dispatch(callbacks.controlUrl);
      if (control.status < 200 || control.status >= 300 || !capturedUrl(control, model.urlField, callbacks.controlUrl)) {
        ctx.logger.warn("Webhook check inconclusive: allowed request failed or payload capture is unavailable"); continue;
      }
      const allowedReceipt = await callbacks.wait("control");
      if (!allowedReceipt) { ctx.logger.warn("Webhook check inconclusive: allowed callback was not observed"); continue; }
      const attempt = await dispatch(callbacks.prohibitedUrl);
      if (!capturedUrl(attempt, model.urlField, callbacks.prohibitedUrl)) {
        ctx.logger.warn("Webhook check inconclusive: tested payload capture is unavailable"); continue;
      }
      const prohibitedReceipt = await callbacks.wait("prohibited");
      if (prohibitedReceipt) {
        const exchanges = [control.exchange, allowedReceipt, attempt.exchange, prohibitedReceipt];
        ctx.report(buildFinding({ probeId: this.manifest.id, family: "ssrf", title: `Policy-forbidden webhook destination contacted on ${endpoint.id}`,
          severity: "HIGH", confidence: "FIRM", cwe: ["CWE-918"], locator: model.urlField,
          target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path, objectRef: endpoint.objectRef },
          affectedIdentities: [model.identity],
          evidence: { summary: "An allowed callback established the control, then the separately owned destination declared forbidden by policy received its fresh test token. This proves the modeled destination-policy violation, not access to internal services.",
            exchanges, auditRefs: exchanges.map((e) => e.ref),
            reproduction: { seed: "see scan config; callback tokens are fresh per run", steps: [
              "Start both owned collectors and model the allowed/forbidden destination policy.",
              "Create a disposable webhook and dispatch the allowed callback as its owner; observe its receipt.",
              "Change only the modeled URL field to the second owned origin and observe its distinct receipt.",
              "Delete the disposable webhook; review the locally retained audit and receipt files.",
            ] } },
          remediation: { guidance: "Enforce the application's destination allow-list before dispatch. Validate resolved addresses and every redirect hop, and enforce outbound network restrictions independently. Recheck destinations at send time for queued webhooks.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"], effort: "moderate" },
        }));
      } else if ([400, 403, 422].includes(attempt.status)) {
        ctx.report({ kind: "pass", probeId: this.manifest.id, family: "ssrf", endpointId: endpoint.id,
          title: `Modeled forbidden callback was explicitly rejected on ${endpoint.id}`,
          summary: `The allowed callback was observed. The forbidden request was explicitly rejected and no matching callback arrived within ${model.timeoutMs} ms. This covers only the modeled destination and observation window, not queued delivery or general SSRF resistance.` });
      } else ctx.logger.warn("Webhook check inconclusive: no forbidden callback, but no explicit rejection either");
    }
  },
};

function capturedUrl(response: GuardedResponse, field: string, url: string): boolean {
  try { return (JSON.parse(response.exchange.request.body ?? "") as Record<string, unknown>)[field] === url; }
  catch { return false; }
}
