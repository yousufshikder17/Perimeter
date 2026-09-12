import { skip, type Probe, type ProbePackage } from "@perimeter/sdk";
import { manifest } from "./manifest.js";

/**
 * __ID__: runnable transport-diagnostic starter, not a vulnerability detector.
 *
 * Safety contract (spec §3.2): all egress via ctx.http (never fetch), all
 * randomness via ctx.rng, all time via ctx.clock, evidence mandatory on every
 * finding, and cooperative cancellation on ctx.signal. `perimeter probe lint`
 * enforces these statically.
 */
export const probe: Probe = {
  manifest,
  async plan(ctx) {
    const endpoint = ctx.target.endpoints.find((e) => e.method === "GET" && e.auth === "none" &&
      !e.graphql && !e.grpc && !e.webhook && !e.csv && !e.objectRef && !e.creates && /^\/(?!\/)[^?#{}\\]*$/.test(e.path) &&
      new URL(e.path, ctx.target.baseUrl).pathname === e.path);
    if (!endpoint) return skip("no explicitly public literal REST GET for the diagnostic starter");
    return { probeId: manifest.id, steps: [{ id: "diagnostic", endpointId: endpoint.id,
      description: "Observe one modeled public GET through the guarded client", estimatedRequests: 1 }] };
  },

  async run(plan, ctx) {
    if (ctx.signal.aborted || !ctx.budget.available()) return;
    const endpoint = ctx.target.endpoints.find((e) => e.id === plan.steps[0]?.endpointId);
    if (!endpoint) return;
    const response = await ctx.http.get(endpoint.path, { maxResponseBytes: 16384 });
    if (response.status === 200) ctx.report({ kind: "pass", probeId: manifest.id, family: manifest.family, endpointId: endpoint.id,
      title: "Diagnostic GET returned 200", summary: "Transport observation only; this is not evidence of security or authorization correctness." });
    else ctx.logger.warn("Diagnostic GET did not return 200", { status: response.status });
  },
};

/**
 * Replace this diagnostic with a reviewed behavior and real vulnerable/patched
 * evidence tests before shipping a security check. Generated tests cover wiring.
 */
export const perimeter: ProbePackage["perimeter"] = { probes: [probe] };
