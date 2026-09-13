import { skip, type FixationSession, type Probe } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";
import { observeJson } from "../_shared/json-observation.js";

export const sessionFixation: Probe = {
  manifest: { id: "auth/session-fixation", family: "auth", version: "0.1.0", schemaVersion: "1",
    requires: { endpoints: ["sessionFixation"] },
    safety: { class: "mutating", maxRequests: 45, destructive: false } },
  async plan(ctx) {
    const endpoints = ctx.target.endpoints.filter((e) => e.sessionReplay?.fixation);
    if (!endpoints.length || !ctx.sessions?.prepareFixation) return skip("no reviewed fixation contract or engine capability");
    return { probeId: this.manifest.id, steps: endpoints.map((e) => ({ id: "fixation:" + e.id, endpointId: e.id,
      description: "Compare a frozen anonymous cookie before and after login, with authenticated controls", estimatedRequests: 9 })) };
  },
  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || ctx.budget.remaining < 9) { ctx.logger.warn("Session fixation incomplete: budget or cancellation"); return; }
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.sessionReplay?.fixation || !ctx.sessions?.prepareFixation) continue;
      const model = endpoint.sessionReplay;
      let fixation: FixationSession | undefined;
      try {
        const anonymous = await ctx.http.get(endpoint.path, { maxResponseBytes: 16384,
          headers: { accept: "application/json", "cache-control": "no-cache, no-store" } });
        const anonymousData = (await anonymous.text()) === anonymous.exchange.response.body ? observeJson(anonymous.exchange, model.resultPath) : undefined;
        if (![401, 403].includes(anonymous.status) || !anonymousData || anonymousData.value !== undefined) {
          ctx.logger.warn("Session fixation inconclusive: protected GET did not deny anonymous access"); continue;
        }
        fixation = await ctx.sessions.prepareFixation(endpoint.id);
        const before = await fixation.read();
        const initial = observeJson(before, model.resultPath);
        if (![401, 403].includes(before.response.status) || !initial || initial.value !== undefined) {
          ctx.logger.warn("Session fixation inconclusive: issued cookie did not establish unauthenticated access"); continue;
        }
        const authenticated = await fixation.login();
        const control = await authenticated.read();
        if (control.response.status !== 200 || observeJson(control, model.resultPath)?.value !== model.expectedValue) {
          ctx.logger.warn("Session fixation inconclusive: login did not establish the expected account"); continue;
        }
        const replay = await fixation.read();
        const after = await authenticated.read();
        if (after.response.status !== 200 || observeJson(after, model.resultPath)?.value !== model.expectedValue) {
          ctx.logger.warn("Session fixation inconclusive: authenticated session did not remain usable"); continue;
        }
        const observed = observeJson(replay, model.resultPath);
        if (observed?.value === model.expectedValue) {
          const exchanges = [anonymous.exchange, fixation.bootstrap, before, control, replay, after];
          ctx.report(buildFinding({ probeId: this.manifest.id, family: "auth",
            title: "Pre-login session gained authenticated access on " + endpoint.id, severity: "HIGH", confidence: "FIRM", cwe: ["CWE-384"],
            target: { endpointId: endpoint.id, method: "GET", path: endpoint.path }, affectedIdentities: [model.identity],
            locator: model.identity + ":" + model.fixation!.bootstrapEndpointId + ":" + JSON.stringify(model.resultPath),
            evidence: { summary: "A freshly issued anonymous cookie was denied before login, then exposed the expected protected account scalar after that account logged in using the same cookie. Authenticated controls before and after replay succeeded.",
              exchanges, auditRefs: exchanges.map((e) => e.ref),
              differential: { baseline: before.ref, probe: replay.ref, diff: "The unchanged pre-login cookie gained protected access, even if login also issued a new cookie." },
              reproduction: { seed: "see scan config", steps: ["Confirm the protected GET denies anonymous access.",
                "Obtain a fresh anonymous session from the reviewed issuer and confirm its cookie is unauthenticated.",
                "Log in the disposable account using that cookie; verify the expected protected account marker.",
                "Read with the original cookie, ignoring all later Set-Cookie values; compare the protected scalar.",
                "Recheck the authenticated session and clean up both owned cookies."] } },
            remediation: { guidance: "Generate a new session identifier on successful authentication and invalidate the pre-login identifier and its aliases. Review whether an attacker could plant the anonymous cookie; this check proves the server-side transition, not a browser delivery mechanism.",
              references: ["https://cwe.mitre.org/data/definitions/384.html", "https://owasp.org/www-community/attacks/Session_fixation"], effort: "moderate" } }));
        } else if (fixation.cookieRotated === true && [401, 403].includes(replay.response.status) && observed && observed.value === undefined) {
          ctx.report({ kind: "pass", probeId: this.manifest.id, family: "auth", endpointId: endpoint.id,
            title: "Pre-login session denied after authentication on " + endpoint.id,
            summary: "Login rotated the session cookie; the original remained denied without the protected scalar while the new session worked before and after replay. Covers only this reviewed cookie/login/read contract." });
        } else ctx.logger.warn("Session fixation inconclusive: no protected-data leak or consistent rotated-session denial");
      } finally {
        await fixation?.close();
      }
    }
  },
};
