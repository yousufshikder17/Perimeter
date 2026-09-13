import { parseTargetModel, type Endpoint, type FixationSession, type HttpExchange, type Probe, type ReplaySession } from "@perimeter/sdk";
import type { EngineDeps } from "../engine/execution-engine.js";
import { GuardedHttpClientImpl } from "../http/guarded-http-client.js";
import type { MutableBudget } from "../runtime/budget.js";
import { SafetyGuard } from "../safety/guard.js";
import { createTokenExchange, readSessionCookie } from "./token-exchange.js";

/** Engine-owned auth lifecycle, not a general POST or credential capability. */
export function createReplaySessions(d: EngineDeps, probe: Probe, budget: MutableBudget) {
  const target = parseTargetModel(structuredClone(d.target));
  const sessions: { handle: ReplaySession; identity: string; allowDeniedLogout: boolean }[] = [];
  const seen = new Set<string>();
  let closed = false;
  function reviewed(endpointId: string) {
      if (closed || !d.allowMutating || probe.manifest.safety.class !== "mutating") {
        throw new Error("Session replay requires an explicitly authorized mutating probe");
      }
      const endpoint = target.endpoints.find((e) => e.id === endpointId);
      if (!endpoint?.sessionReplay) throw new Error("Unmodeled session-replay endpoint");
      return endpoint;
  }
  function client(endpoint: Endpoint, url: string, captureBodies: boolean, cookie?: string) {
    const spec = target.identities.find((i) => i.ref === endpoint.sessionReplay!.identity)!;
    return new GuardedHttpClientImpl({
        baseUrl: target.baseUrl, probeId: probe.manifest.id, probeSafetyClass: "mutating",
        guard: new SafetyGuard({ allowedHosts: new Set([new URL(target.baseUrl).host]), allowMutating: true,
          scratchObjectIds: new Set(), authenticationUrls: new Set([new URL(url, target.baseUrl).href]) }),
        budget, limiter: d.limiter, audit: d.audit, scanId: d.scanId, signal: d.signal,
        captureBodies, maxResponseBytes: Math.min(d.maxResponseBytes ?? 16384, 16384),
        resolveIdentity: () => ({ ref: spec.ref, tenant: spec.tenant, role: spec.role,
          headers: async () => cookie ? { cookie } : {} }),
    });
  }
  function track(endpoint: Endpoint, cookie: string, allowDeniedLogout = false, strictReads = false) {
      const model = endpoint.sessionReplay!;
      const logoutEndpoint = target.endpoints.find((e) => e.id === model.logoutEndpointId)!;
      const http = client(endpoint, logoutEndpoint.path, d.captureBodies !== false, cookie);
      const headers = { accept: "application/json", "cache-control": "no-cache, no-store", "content-type": "application/json" };
      let logout: Promise<HttpExchange> | undefined;
      const handle: ReplaySession = {
        async read() {
          if (closed) throw new Error("Session replay scope is closed");
          const response = await http.get(endpoint.path, { as: model.identity, headers });
          let stableCookie = true;
          if (strictReads && response.setCookies?.some((value) => value.startsWith(`${target.auth.login!.cookieName}=`))) {
            try { stableCookie = readSessionCookie(response, target.auth.login!.cookieName, 3600).headers.cookie === cookie; }
            catch { stableCookie = false; }
          }
          // A changed/truncated/redacted capture cannot prove either leakage or denial.
          return stableCookie && (await response.text()) === response.exchange.response.body ? response.exchange :
            { ...response.exchange, response: { ...response.exchange.response, body: undefined } };
        },
        async logout() {
          if (closed) throw new Error("Session replay scope is closed");
          // Retain the original cookie even if logout clears or rotates Set-Cookie.
          logout ??= http.request({ method: "POST", url: logoutEndpoint.path, as: model.identity, headers,
            body: JSON.stringify(model.logoutBody) }).then((response) => response.exchange);
          return logout;
        },
      };
      const entry = { handle, identity: model.identity, allowDeniedLogout };
      sessions.push(entry);
      return entry;
  }
  async function cleanupSession(entry: typeof sessions[number]) {
    try {
      const response = await entry.handle.logout();
      if (![200, 204, ...(entry.allowDeniedLogout ? [401, 403] : [])].includes(response.response.status)) throw new Error();
    } catch { d.logger.warn("Disposable-session logout incomplete; operator cleanup may be required"); }
    finally { d.identities.invalidate(entry.identity); }
  }
  return {
    async open(endpointId: string): Promise<ReplaySession> {
      const endpoint = reviewed(endpointId);
      const spec = target.identities.find((i) => i.ref === endpoint.sessionReplay!.identity)!;
      const credential = await createTokenExchange(target, client(endpoint, target.auth.tokenEndpoint!, false))(spec.ref, spec.credentials!.env);
      const cookie = credential.headers.cookie!;
      const entry = track(endpoint, cookie);
      if (seen.has(cookie)) throw new Error("Session replay inconclusive: login reused an earlier cookie");
      seen.add(cookie);
      return entry.handle;
    },
    async prepareFixation(endpointId: string): Promise<FixationSession> {
      const endpoint = reviewed(endpointId);
      const model = endpoint.sessionReplay!;
      if (!model.fixation) throw new Error("Unmodeled session-fixation bootstrap");
      const bootstrapEndpoint = target.endpoints.find((e) => e.id === model.fixation!.bootstrapEndpointId)!;
      const started = d.clock.now();
      const bootstrap = await client(endpoint, target.auth.tokenEndpoint!, false).get(bootstrapEndpoint.path,
        { headers: { "cache-control": "no-cache, no-store" } });
      if (bootstrap.status !== 200 || Number(bootstrap.headers.age ?? 0) > 0) throw new Error("Session bootstrap did not return a fresh successful response");
      const anonymous = readSessionCookie(bootstrap, target.auth.login!.cookieName, 3600);
      const cookie = anonymous.headers.cookie;
      const expiresAt = started + anonymous.ttlSeconds * 1000;
      const original = track(endpoint, cookie, true, true);
      if (seen.has(cookie)) throw new Error("Session bootstrap reused an earlier cookie");
      seen.add(cookie);
      let authenticated: typeof original | undefined;
      let login: Promise<ReplaySession> | undefined;
      let closing = false;
      return {
        bootstrap: bootstrap.exchange,
        get cookieRotated() { return authenticated ? authenticated !== original : undefined; },
        async read() {
          if (closing) throw new Error("Session fixation scope is closed");
          if (d.clock.now() >= expiresAt) throw new Error("Anonymous session lifetime elapsed; fixation check inconclusive");
          const response = await original.handle.read();
          if (d.clock.now() >= expiresAt) throw new Error("Anonymous session lifetime elapsed; fixation check inconclusive");
          return response;
        },
        async login() {
          if (closing || closed) throw new Error("Session fixation scope is closed");
          if (d.clock.now() >= expiresAt) throw new Error("Anonymous session lifetime elapsed; fixation check inconclusive");
          login ??= (async () => {
            const spec = target.identities.find((i) => i.ref === model.identity)!;
            const credential = await createTokenExchange(target, client(endpoint, target.auth.tokenEndpoint!, false), cookie)(spec.ref, spec.credentials!.env);
            const current = credential.headers.cookie!;
            authenticated = current === cookie ? original : track(endpoint, current, false, true);
            if (current !== cookie && seen.has(current)) throw new Error("Session login reused an earlier cookie");
            seen.add(current);
            return authenticated.handle;
          })();
          return login;
        },
        async close() {
          closing = true;
          await login?.catch(() => {});
          await cleanupSession(original);
          if (authenticated && authenticated !== original) await cleanupSession(authenticated);
        },
      };
    },
    async cleanup(): Promise<void> {
      if (closed) return;
      for (const entry of sessions) await cleanupSession(entry);
      closed = true;
      sessions.length = 0;
      seen.clear();
    },
  };
}
