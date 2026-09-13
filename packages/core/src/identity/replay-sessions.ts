import { parseTargetModel, type HttpExchange, type Probe, type ReplaySession } from "@perimeter/sdk";
import type { EngineDeps } from "../engine/execution-engine.js";
import { GuardedHttpClientImpl } from "../http/guarded-http-client.js";
import type { MutableBudget } from "../runtime/budget.js";
import { SafetyGuard } from "../safety/guard.js";
import { createTokenExchange } from "./token-exchange.js";

/** Engine-owned auth lifecycle, not a general POST or credential capability. */
export function createReplaySessions(d: EngineDeps, probe: Probe, budget: MutableBudget) {
  const target = parseTargetModel(structuredClone(d.target));
  const sessions: { handle: ReplaySession; identity: string }[] = [];
  const seen = new Set<string>();
  let closed = false;
  return {
    async open(endpointId: string): Promise<ReplaySession> {
      if (closed || !d.allowMutating || probe.manifest.safety.class !== "mutating") {
        throw new Error("Session replay requires an explicitly authorized mutating probe");
      }
      const endpoint = target.endpoints.find((e) => e.id === endpointId);
      if (!endpoint?.sessionReplay) throw new Error("Unmodeled session-replay endpoint");
      const model = endpoint.sessionReplay;
      const spec = target.identities.find((i) => i.ref === model.identity)!;
      const logoutEndpoint = target.endpoints.find((e) => e.id === model.logoutEndpointId)!;
      const client = (url: string, captureBodies: boolean, cookie?: string) => new GuardedHttpClientImpl({
        baseUrl: target.baseUrl, probeId: probe.manifest.id, probeSafetyClass: "mutating",
        guard: new SafetyGuard({ allowedHosts: new Set([new URL(target.baseUrl).host]), allowMutating: true,
          scratchObjectIds: new Set(), authenticationUrls: new Set([new URL(url, target.baseUrl).href]) }),
        budget, limiter: d.limiter, audit: d.audit, scanId: d.scanId, signal: d.signal,
        captureBodies, maxResponseBytes: Math.min(d.maxResponseBytes ?? 16384, 16384),
        resolveIdentity: () => ({ ref: spec.ref, tenant: spec.tenant, role: spec.role,
          headers: async () => cookie ? { cookie } : {} }),
      });
      const credential = await createTokenExchange(target, client(target.auth.tokenEndpoint!, false))(spec.ref, spec.credentials!.env);
      const cookie = credential.headers.cookie!;
      const http = client(logoutEndpoint.path, d.captureBodies !== false, cookie);
      const headers = { accept: "application/json", "cache-control": "no-cache, no-store", "content-type": "application/json" };
      let logout: Promise<HttpExchange> | undefined;
      const handle: ReplaySession = {
        async read() {
          if (closed) throw new Error("Session replay scope is closed");
          const response = await http.get(endpoint.path, { as: spec.ref, headers });
          // A changed/truncated/redacted capture cannot prove either leakage or denial.
          return (await response.text()) === response.exchange.response.body ? response.exchange :
            { ...response.exchange, response: { ...response.exchange.response, body: undefined } };
        },
        async logout() {
          if (closed) throw new Error("Session replay scope is closed");
          // Retain the original cookie even if logout clears or rotates Set-Cookie.
          logout ??= http.request({ method: "POST", url: logoutEndpoint.path, as: spec.ref, headers,
            body: JSON.stringify(model.logoutBody) }).then((response) => response.exchange);
          return logout;
        },
      };
      sessions.push({ handle, identity: spec.ref });
      if (seen.has(cookie)) throw new Error("Session replay inconclusive: login reused an earlier cookie");
      seen.add(cookie);
      return handle;
    },
    async cleanup(): Promise<void> {
      if (closed) return;
      for (const { handle, identity } of sessions) {
        try {
          const response = await handle.logout();
          if (![200, 204].includes(response.response.status)) throw new Error();
        } catch { d.logger.warn("Disposable-session logout incomplete; operator cleanup may be required"); }
        finally { d.identities.invalidate(identity); }
      }
      closed = true;
      sessions.length = 0;
      seen.clear();
    },
  };
}
