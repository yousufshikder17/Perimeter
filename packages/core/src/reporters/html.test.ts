import { describe, expect, it } from "vitest";
import type { FindingRegistry } from "@perimeter/sdk";
import { HtmlReporter } from "./html.js";

describe("HTML reporter", () => {
  it("renders a self-contained report and escapes finding content", () => {
    const registry = {
      schemaVersion: "1.0",
      scanId: "scan-1",
      target: "staging <script>alert(1)</script>",
      seed: "seed-1",
      startedAt: "2026-09-03T00:00:00.000Z",
      finishedAt: "2026-09-03T00:01:00.000Z",
      findings: [
        {
          id: "finding-1",
          fingerprint: "fingerprint-1",
          schemaVersion: "1.0",
          probeId: "idor/object-read",
          family: "idor",
          title: "Cross-tenant <access>",
          severity: "HIGH",
          confidence: "CONFIRMED",
          target: { endpointId: "read", method: "GET", path: "/objects/{id}" },
          affectedIdentities: ["tenantA.user"],
          evidence: {
            summary: "Tenant B data was returned",
            exchanges: [],
            reproduction: { seed: "seed-1", steps: ["Request the foreign object"] },
            auditRefs: [],
          },
          remediation: { guidance: "Check ownership", references: [] },
          firstSeen: "2026-09-03T00:00:00.000Z",
          lastSeen: "2026-09-03T00:00:00.000Z",
          status: "open",
        },
      ],
      passes: [],
      skipped: [],
    } as FindingRegistry;

    const html = new HtmlReporter().render(registry);

    expect(html).toContain("<!doctype html>");
    expect(html).toContain("Cross-tenant &lt;access&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("Content-Security-Policy");
  });
});
