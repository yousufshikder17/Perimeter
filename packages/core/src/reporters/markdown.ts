import type { Finding, FindingRegistry, Severity } from "@perimeter/sdk";
import type { Reporter } from "./index.js";

/**
 * Markdown reporter (spec §6.5) — the default artifact a developer reads:
 * executive summary, severity rollup, per-finding detail with evidence and
 * remediation, plus explicit passes and skips.
 */
export class MarkdownReporter implements Reporter {
  readonly name = "markdown";
  readonly extension = "md";

  render(r: FindingRegistry): string {
    const lines: string[] = [];
    lines.push(`# Perimeter scan report`, "");
    lines.push(`**Target:** ${r.target}  `);
    lines.push(`**Scan:** \`${r.scanId}\` · **Seed:** \`${r.seed}\`  `);
    lines.push(`**Window:** ${r.startedAt} → ${r.finishedAt}  `);
    lines.push(`**Schema:** v${r.schemaVersion}`, "");

    lines.push(`## Summary`, "", this.#rollup(r.findings), "");

    if (r.findings.length) {
      lines.push(`## Findings`, "");
      for (const f of sortBySeverity(r.findings)) lines.push(...this.#finding(f));
    } else {
      lines.push(`## Findings`, "", `No findings. 🎉`, "");
    }

    if (r.passes.length) {
      lines.push(`## Passes`, "");
      for (const p of r.passes) lines.push(`- **${p.title}** — ${p.summary}`);
      lines.push("");
    }

    if (r.skipped.length) {
      lines.push(`## Skipped probes`, "");
      for (const s of r.skipped) lines.push(`- \`${s.probeId}\` — ${s.reason}`);
      lines.push("");
    }
    return lines.join("\n");
  }

  #rollup(findings: readonly Finding[]): string {
    const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of findings) if (f.status === "open") counts[f.severity]++;
    return [
      "| Severity | Count |",
      "|---|---|",
      ...(Object.keys(counts) as Severity[]).map((s) => `| ${s} | ${counts[s]} |`),
    ].join("\n");
  }

  #finding(f: Finding): string[] {
    const out: string[] = [];
    out.push(`### ${severityBadge(f.severity)} ${f.title}`, "");
    out.push(`- **Probe:** \`${f.probeId}\` (${f.family})`);
    out.push(`- **Confidence:** ${f.confidence} · **Status:** ${f.status}`);
    out.push(`- **Endpoint:** \`${f.target.method} ${f.target.path}\` (${f.target.endpointId})`);
    out.push(`- **Affected identities:** ${f.affectedIdentities.join(", ") || "—"}`);
    if (f.cwe?.length) out.push(`- **CWE:** ${f.cwe.join(", ")}`);
    if (f.owaspApi?.length) out.push(`- **OWASP API:** ${f.owaspApi.join(", ")}`);
    out.push(`- **Fingerprint:** \`${f.fingerprint}\``, "");
    out.push(`**Evidence.** ${f.evidence.summary}`, "");
    if (f.evidence.differential) {
      out.push("```diff", f.evidence.differential.diff, "```", "");
    }
    if (f.evidence.reproduction.curl?.length) {
      out.push("Reproduce (redacted):", "", "```bash", ...f.evidence.reproduction.curl, "```", "");
    }
    out.push(`**Remediation.** ${f.remediation.guidance}`);
    if (f.remediation.codeHints?.length) {
      out.push("", ...f.remediation.codeHints.map((h) => `- ${h}`));
    }
    if (f.remediation.references.length) {
      out.push("", "References: " + f.remediation.references.map((x) => `<${x}>`).join(", "));
    }
    out.push("", "---", "");
    return out;
  }
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function sortBySeverity(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
}

function severityBadge(s: Severity): string {
  return { CRITICAL: "🟥", HIGH: "🟧", MEDIUM: "🟨", LOW: "🟦", INFO: "⬜" }[s];
}
