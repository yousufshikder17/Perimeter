import type { Finding, FindingRegistry } from "@perimeter/sdk";
import { escapeHtml } from "../reporters/html.js";

export const COMPARISON_SCHEMA_VERSION = "1.0" as const;

export interface ScanComparison {
  schemaVersion: typeof COMPARISON_SCHEMA_VERSION;
  target: string;
  previousScanId: string;
  currentScanId: string;
  newFindings: Finding[];
  unchangedFindings: Finding[];
  resolvedFindings: Finding[];
}

export function compareScans(previous: FindingRegistry, current: FindingRegistry): ScanComparison {
  if (previous.target !== current.target) {
    throw new Error(
      `cannot compare different targets: "${previous.target}" and "${current.target}"`,
    );
  }

  const previousByFingerprint = uniqueFindings(previous.findings);
  const currentByFingerprint = uniqueFindings(current.findings);

  return {
    schemaVersion: COMPARISON_SCHEMA_VERSION,
    target: current.target,
    previousScanId: previous.scanId,
    currentScanId: current.scanId,
    newFindings: [...currentByFingerprint.values()].filter(
      (finding) => !previousByFingerprint.has(finding.fingerprint),
    ),
    unchangedFindings: [...currentByFingerprint.values()].filter((finding) =>
      previousByFingerprint.has(finding.fingerprint),
    ),
    resolvedFindings: [...previousByFingerprint.values()].filter(
      (finding) => !currentByFingerprint.has(finding.fingerprint),
    ),
  };
}

export function renderComparisonJson(comparison: ScanComparison): string {
  return JSON.stringify(comparison, null, 2) + "\n";
}

export function renderComparisonMarkdown(comparison: ScanComparison): string {
  return [
    "# Perimeter scan comparison",
    "",
    `**Target:** ${comparison.target}  `,
    `**Previous:** \`${comparison.previousScanId}\`  `,
    `**Current:** \`${comparison.currentScanId}\``,
    "",
    `| New | Unchanged | Resolved |`,
    `|---:|---:|---:|`,
    `| ${comparison.newFindings.length} | ${comparison.unchangedFindings.length} | ${comparison.resolvedFindings.length} |`,
    "",
    markdownGroup("New findings", comparison.newFindings),
    markdownGroup("Unchanged findings", comparison.unchangedFindings),
    markdownGroup("Resolved findings", comparison.resolvedFindings),
  ].join("\n");
}

export function renderComparisonHtml(comparison: ScanComparison): string {
  return `<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <title>Perimeter scan comparison — ${escapeHtml(comparison.target)}</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #0b0d10; color: #e8ebef; }
    main { width: min(1000px, calc(100% - 32px)); margin: 0 auto; padding: 48px 0 80px; }
    h1 { font-size: clamp(2rem, 5vw, 4rem); letter-spacing: -.04em; margin-bottom: 8px; }
    p, li { color: #b4bbc5; line-height: 1.55; }
    code { color: #d8dee8; overflow-wrap: anywhere; }
    .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 28px 0 44px; }
    .metric, li { border: 1px solid #2a3038; background: #12161b; }
    .metric { padding: 18px; } .metric strong { display: block; font-size: 2rem; }
    ul { list-style: none; padding: 0; } li { margin: 10px 0; padding: 14px; }
    .severity { float: right; font-size: .75rem; font-weight: 700; }
    @media (max-width: 560px) { .metrics { grid-template-columns: 1fr; } }
  </style>
</head><body><main>
  <header><span>Perimeter security report</span><h1>Scan comparison</h1>
    <p><strong>${escapeHtml(comparison.target)}</strong><br><code>${escapeHtml(comparison.previousScanId)}</code> → <code>${escapeHtml(comparison.currentScanId)}</code></p>
  </header>
  <div class="metrics">
    <div class="metric"><span>New</span><strong>${comparison.newFindings.length}</strong></div>
    <div class="metric"><span>Unchanged</span><strong>${comparison.unchangedFindings.length}</strong></div>
    <div class="metric"><span>Resolved</span><strong>${comparison.resolvedFindings.length}</strong></div>
  </div>
  ${htmlGroup("New findings", comparison.newFindings)}
  ${htmlGroup("Unchanged findings", comparison.unchangedFindings)}
  ${htmlGroup("Resolved findings", comparison.resolvedFindings)}
</main></body></html>\n`;
}

function uniqueFindings(findings: readonly Finding[]): Map<string, Finding> {
  return new Map(findings.map((finding) => [finding.fingerprint, finding]));
}

function markdownGroup(title: string, findings: Finding[]): string {
  return [
    `## ${title}`,
    "",
    ...(findings.length
      ? findings.map(
          (finding) =>
            `- **${finding.severity}** ${finding.title} — \`${finding.target.method} ${finding.target.path}\` — \`${finding.fingerprint}\``,
        )
      : ["None."]),
    "",
  ].join("\n");
}

function htmlGroup(title: string, findings: Finding[]): string {
  const items = findings.length
    ? `<ul>${findings
        .map(
          (finding) =>
            `<li><span class="severity">${finding.severity}</span><strong>${escapeHtml(finding.title)}</strong><br><code>${escapeHtml(`${finding.target.method} ${finding.target.path}`)}</code><br><code>${escapeHtml(finding.fingerprint)}</code></li>`,
        )
        .join("")}</ul>`
    : "<p>None.</p>";
  return `<section><h2>${title}</h2>${items}</section>`;
}
