import type { Finding, FindingRegistry, Severity } from "@perimeter/sdk";
import type { Reporter } from "./index.js";

/**
 * SARIF 2.1.0 reporter (spec §6.5) — unlocks GitHub Advanced Security /
 * code-scanning inline PR annotations. Each finding becomes a `result`; each
 * probe id becomes a `rule`.
 */
export class SarifReporter implements Reporter {
  readonly name = "sarif";
  readonly extension = "sarif";

  render(r: FindingRegistry): string {
    const rules = dedupeRules(r.findings);
    const sarif = {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Perimeter",
              informationUri: "https://github.com/perimeter/perimeter",
              version: r.schemaVersion,
              rules,
            },
          },
          results: r.findings.map((f) => this.#result(f)),
        },
      ],
    };
    return JSON.stringify(sarif, null, 2) + "\n";
  }

  #result(f: Finding) {
    return {
      ruleId: f.probeId,
      level: sarifLevel(f.severity),
      message: { text: `${f.title} — ${f.evidence.summary}` },
      partialFingerprints: { perimeterFingerprint: f.fingerprint },
      properties: {
        severity: f.severity,
        confidence: f.confidence,
        cwe: f.cwe ?? [],
        owaspApi: f.owaspApi ?? [],
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.target.path },
          },
          logicalLocations: [{ fullyQualifiedName: `${f.target.method} ${f.target.endpointId}` }],
        },
      ],
    };
  }
}

function dedupeRules(findings: readonly Finding[]) {
  const seen = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
  for (const f of findings) {
    if (!seen.has(f.probeId)) {
      seen.set(f.probeId, {
        id: f.probeId,
        name: f.probeId,
        shortDescription: { text: `${f.family} probe: ${f.probeId}` },
      });
    }
  }
  return [...seen.values()];
}

/** SARIF only has error/warning/note/none — map Perimeter severities down. */
function sarifLevel(s: Severity): "error" | "warning" | "note" {
  switch (s) {
    case "CRITICAL":
    case "HIGH":
      return "error";
    case "MEDIUM":
    case "LOW":
      return "warning";
    default:
      return "note";
  }
}
