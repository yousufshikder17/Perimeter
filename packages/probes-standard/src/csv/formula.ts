import { skip, type Probe } from "@perimeter/sdk";
import { buildFinding } from "../_shared/findings.js";
import { parseCsv } from "./parse.js";

export const csvFormula: Probe = {
  manifest: {
    id: "csv/formula", family: "csv", version: "0.1.0", schemaVersion: "1",
    requires: { allIdentities: true, endpoints: ["csvExport"] },
    safety: { class: "read-only", maxRequests: 20, destructive: false },
  },
  async plan(ctx) {
    const endpoints = ctx.target.endpoints.filter((e) => e.csv && !e.graphql);
    if (!endpoints.length) return skip("no reviewed CSV export canary");
    return { probeId: this.manifest.id, steps: endpoints.map((e) => ({ id: `csv:${e.id}`, endpointId: e.id,
      description: `Inspect the scratch canary in CSV export ${e.id}`, estimatedRequests: 1 })) };
  },
  async run(plan, ctx) {
    for (const step of plan.steps) {
      if (ctx.signal.aborted || !ctx.budget.available()) return;
      const endpoint = ctx.target.endpoints.find((e) => e.id === step.endpointId);
      if (!endpoint?.csv || !endpoint.objectRef) continue;
      const model = endpoint.csv;
      const fixture = ctx.fixtures.owned(endpoint.objectRef.kind, model.identity);
      if (!fixture) { ctx.logger.warn("CSV check omitted: missing scratch canary", { endpoint: endpoint.id }); continue; }
      const response = await ctx.http.get(endpoint.path.replace(`{${endpoint.objectRef.param}}`, encodeURIComponent(fixture.id)), {
        as: model.identity, headers: { accept: "text/csv" }, maxResponseBytes: 16384,
      });
      const text = await response.text();
      let value: string;
      try {
        if (response.status !== 200 || !/^text\/csv(?:\s*;|$)/i.test(response.headers["content-type"] ?? "") ||
            text !== response.exchange.response.body) throw new Error();
        const [header, ...rows] = parseCsv(text, model.delimiter);
        if (!header || new Set(header).size !== header.length) throw new Error();
        const idIndex = header.indexOf(model.idColumn);
        const columnIndex = header.indexOf(model.column);
        const matches = rows.filter((r) => r[idIndex] === fixture.id);
        if (idIndex < 0 || columnIndex < 0 || matches.length !== 1) throw new Error();
        value = matches[0]![columnIndex]!;
      } catch {
        ctx.logger.warn("CSV check inconclusive: incomplete CSV evidence or missing/ambiguous scratch row", { endpoint: endpoint.id });
        continue;
      }
      if (value === model.canary) {
        ctx.report(buildFinding({
          probeId: this.manifest.id, family: "csv", title: `Formula canary exported without text neutralization on ${endpoint.id}`,
          severity: "MEDIUM", confidence: "FIRM", cwe: ["CWE-1236"],
          target: { endpointId: endpoint.id, method: endpoint.method, path: endpoint.path, tenantScoped: endpoint.tenantScoped },
          affectedIdentities: [model.identity], locator: model.column,
          evidence: { summary: "A harmless formula seeded in an engine-created object remained an active formula-shaped CSV cell. CSV quoting alone did not neutralize it; spreadsheet execution was not attempted.",
            exchanges: [response.exchange], auditRefs: [response.exchange.ref],
            reproduction: { seed: "see scan config", steps: ["Create the reviewed scratch fixture containing the harmless canary.",
              `Export as ${model.identity}; locate the scratch ID in ${model.idColumn} and inspect ${model.column}.`] } },
          remediation: { guidance: "Serialize CSV correctly and neutralize untrusted formula-leading cells for the intended spreadsheet importer. Verify import and save/reopen behavior; do not treat CSV quoting as formula protection.",
            references: ["https://owasp.org/www-community/attacks/CSV_Injection"], effort: "moderate" },
        }));
      } else if (value === `'${model.canary}`) {
        ctx.report({ kind: "pass", probeId: this.manifest.id, family: "csv", endpointId: endpoint.id,
          title: `CSV canary text-prefixed on ${endpoint.id}`, summary: "The exact scratch canary has an apostrophe text prefix. This bounded observation does not certify every spreadsheet importer or save/reopen cycle." });
      } else ctx.logger.warn("CSV check inconclusive: canary transformed or absent from selected cell", { endpoint: endpoint.id });
    }
  },
};
