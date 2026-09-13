import { skip, type Probe, type ReplaySession } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";
import { observeJson } from "../_shared/json-observation.js";

export const sessionReplay: Probe = {
  manifest: { id: "auth/session-replay", family: "auth", version: "0.1.0", schemaVersion: "1",
    requires: { endpoints: ["sessionReplay"] },
    safety: { class: "mutating", maxRequests: 40, destructive: false } },
  async plan(ctx) {
    const endpoints = ctx.target.endpoints.filter((e) => e.sessionReplay);
    if (!endpoints.length || !ctx.sessions) return skip("no reviewed session-replay contract or engine session capability");
    return { probeId: this.manifest.id, steps: endpoints.map((e) => ({ id: `session:${e.id}`, endpointId: e.id,
      description: "Replay the original cookie after reviewed logout, with anonymous and fresh-session controls", estimatedRequests: 8 })) };
  },
  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || ctx.budget.remaining < 8) { ctx.logger.warn("Session replay incomplete: budget or cancellation"); return; }
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.sessionReplay || !ctx.sessions) continue;
      const model = endpoint.sessionReplay;
      let original: ReplaySession | undefined;
      let fresh: ReplaySession | undefined;
      try {
        const anonymous = await ctx.http.get(endpoint.path, { maxResponseBytes: 16384,
          headers: { accept: "application/json", "cache-control": "no-cache, no-store" } });
        const anonymousData = (await anonymous.text()) === anonymous.exchange.response.body ? observeJson(anonymous.exchange, model.resultPath) : undefined;
        if (![401, 403].includes(anonymous.status) || !anonymousData || anonymousData.value !== undefined) {
          ctx.logger.warn("Session replay inconclusive: protected GET did not establish anonymous denial"); continue;
        }
        original = await ctx.sessions.open(endpoint.id);
        const before = await original.read();
        if (before.response.status !== 200 || observeJson(before, model.resultPath)?.value !== model.expectedValue) {
          ctx.logger.warn("Session replay inconclusive: fresh login did not establish the expected protected identity"); continue;
        }
        const logout = await original.logout();
        if (logout.response.status !== model.logoutSuccessStatus) {
          ctx.logger.warn("Session replay inconclusive: logout did not acknowledge success"); continue;
        }
        const replay = await original.read();
        fresh = await ctx.sessions.open(endpoint.id);
        const control = await fresh.read();
        if (control.response.status !== 200 || observeJson(control, model.resultPath)?.value !== model.expectedValue) {
          ctx.logger.warn("Session replay inconclusive: independent fresh-session control failed"); continue;
        }
        const observed = observeJson(replay, model.resultPath);
        if (observed?.value === model.expectedValue) {
          const exchanges = [anonymous.exchange, before, logout, replay, control];
          ctx.report(buildFinding({ probeId: this.manifest.id, family: "auth", title: `Logged-out session still exposes protected data on ${endpoint.id}`,
            severity: "HIGH", confidence: "FIRM", cwe: ["CWE-613"],
            target: { endpointId: endpoint.id, method: "GET", path: endpoint.path }, affectedIdentities: [model.identity],
            locator: `${model.identity}:${model.logoutEndpointId}:${JSON.stringify(model.resultPath)}`,
            evidence: { summary: "After the reviewed logout acknowledged success, the original unchanged cookie still returned the expected protected identity scalar. Anonymous denial and a distinct fresh-login control both succeeded.",
              exchanges, auditRefs: exchanges.map((e) => e.ref),
              differential: { baseline: before.ref, probe: replay.ref, diff: "The same protected scalar remained visible with the original cookie after logout, regardless of HTTP status." },
              reproduction: { seed: "see scan config", steps: ["Confirm the protected GET denies anonymous access.",
                "Log in using the disposable account and verify its expected protected scalar.",
                "POST the reviewed current-session logout and require its declared success status.",
                "Repeat the GET with the exact original cookie, ignoring Set-Cookie changes.",
                "Verify the same account still works with a distinct fresh session, then log out that session."] } },
            remediation: { guidance: "Invalidate the current session server-side at logout and reject that session on every protected handler. Clearing the browser cookie alone is insufficient. Verify the reviewed logout contract and account marker when triaging.",
              references: ["https://cwe.mitre.org/data/definitions/613.html"], effort: "moderate" } }));
        } else if ([401, 403].includes(replay.response.status) && observed && observed.value === undefined) {
          ctx.report({ kind: "pass", probeId: this.manifest.id, family: "auth", endpointId: endpoint.id,
            title: `Logged-out session denied on ${endpoint.id}`, summary: "The original cookie received 401/403 without the protected scalar after acknowledged logout, while a distinct fresh session worked. Covers only this immediate read/logout contract." });
        } else ctx.logger.warn("Session replay inconclusive: neither matching protected data nor an unambiguous denial");
      } finally {
        // Settle each endpoint's session writes before spending the next step's budget.
        for (const session of [original, fresh]) if (session) {
          try { await session.logout(); }
          catch { ctx.logger.warn("Session cleanup incomplete; operator cleanup may be required"); }
        }
      }
    }
  },
};
