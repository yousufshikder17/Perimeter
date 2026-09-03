import type { Finding, FindingRegistry, Severity } from "@perimeter/sdk";
import type { Reporter } from "./index.js";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/** Self-contained, script-free report for local review and artifact hosting. */
export class HtmlReporter implements Reporter {
  readonly name = "html";
  readonly extension = "html";

  render(registry: FindingRegistry): string {
    const counts = Object.fromEntries(
      SEVERITIES.map((severity) => [
        severity,
        registry.findings.filter(
          (finding) => finding.status === "open" && finding.severity === severity,
        ).length,
      ]),
    ) as Record<Severity, number>;
    const findings = [...registry.findings]
      .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
      .map(renderFinding)
      .join("");

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <title>Perimeter scan report — ${escapeHtml(registry.target)}</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #0b0d10; color: #e8ebef; }
    * { box-sizing: border-box; }
    body { margin: 0; }
    main { width: min(1120px, calc(100% - 32px)); margin: 0 auto; padding: 48px 0 80px; }
    header { border-bottom: 1px solid #2a3038; padding-bottom: 28px; }
    h1 { margin: 0 0 10px; font-size: clamp(2rem, 5vw, 4rem); letter-spacing: -.04em; }
    h2 { margin-top: 44px; }
    h3 { margin: 0; font-size: 1.1rem; }
    p { color: #b4bbc5; line-height: 1.6; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
    code { color: #d8dee8; }
    pre { overflow: auto; padding: 14px; border: 1px solid #303640; background: #101318; white-space: pre-wrap; }
    .meta, .grid { display: grid; gap: 12px; }
    .meta { grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); margin-top: 24px; }
    .meta div, .metric, article { border: 1px solid #2a3038; background: #12161b; }
    .meta div { padding: 14px; }
    .label { display: block; color: #89929e; font-size: .75rem; letter-spacing: .08em; text-transform: uppercase; }
    .grid { grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); }
    .metric { padding: 16px; }
    .metric strong { display: block; margin-top: 5px; font-size: 1.6rem; }
    article { margin: 16px 0; padding: 20px; border-left: 4px solid var(--severity); }
    .finding-head { display: flex; justify-content: space-between; gap: 16px; align-items: start; }
    .badge { padding: 4px 8px; border: 1px solid var(--severity); color: var(--severity); font-size: .75rem; font-weight: 700; }
    dl { display: grid; grid-template-columns: max-content 1fr; gap: 7px 18px; }
    dt { color: #89929e; }
    dd { margin: 0; overflow-wrap: anywhere; }
    .CRITICAL { --severity: #ff5c67; } .HIGH { --severity: #ff985c; } .MEDIUM { --severity: #f0c75e; }
    .LOW { --severity: #6aa9ff; } .INFO { --severity: #9aa4b2; }
    .empty { padding: 24px; border: 1px dashed #39414c; color: #b4bbc5; }
    li { margin: 7px 0; color: #b4bbc5; }
    @media (max-width: 620px) { main { width: min(100% - 20px, 1120px); padding-top: 24px; } dl { grid-template-columns: 1fr; } dd { margin-bottom: 8px; } }
  </style>
</head>
<body><main>
  <header>
    <span class="label">Perimeter security report</span>
    <h1>${escapeHtml(registry.target)}</h1>
    <div class="meta">
      <div><span class="label">Scan</span><code>${escapeHtml(registry.scanId)}</code></div>
      <div><span class="label">Seed</span><code>${escapeHtml(registry.seed)}</code></div>
      <div><span class="label">Started</span>${escapeHtml(registry.startedAt)}</div>
      <div><span class="label">Finished</span>${escapeHtml(registry.finishedAt)}</div>
    </div>
  </header>
  <section aria-labelledby="summary"><h2 id="summary">Summary</h2><div class="grid">
    ${SEVERITIES.map((severity) => `<div class="metric ${severity}"><span class="label">${severity}</span><strong>${counts[severity]}</strong></div>`).join("")}
    <div class="metric"><span class="label">Accepted</span><strong>${registry.findings.filter((finding) => finding.status === "accepted").length}</strong></div>
  </div></section>
  <section aria-labelledby="findings"><h2 id="findings">Findings</h2>${findings || '<div class="empty">No findings.</div>'}</section>
  ${renderList(
    "Passes",
    registry.passes.map(
      (pass) => `<strong>${escapeHtml(pass.title)}</strong> — ${escapeHtml(pass.summary)}`,
    ),
  )}
  ${renderList(
    "Skipped probes",
    registry.skipped.map(
      (skip) => `<code>${escapeHtml(skip.probeId)}</code> — ${escapeHtml(skip.reason)}`,
    ),
  )}
</main></body>
</html>\n`;
  }
}

function renderFinding(finding: Finding): string {
  const differential = finding.evidence.differential?.diff;
  const curls = finding.evidence.reproduction.curl;
  return `<article class="${finding.severity}">
    <div class="finding-head"><h3>${escapeHtml(finding.title)}</h3><span class="badge">${finding.severity}</span></div>
    <dl>
      <dt>Status</dt><dd>${escapeHtml(finding.status)}</dd>
      <dt>Confidence</dt><dd>${escapeHtml(finding.confidence)}</dd>
      <dt>Probe</dt><dd><code>${escapeHtml(finding.probeId)}</code></dd>
      <dt>Endpoint</dt><dd><code>${escapeHtml(`${finding.target.method} ${finding.target.path}`)}</code></dd>
      <dt>Fingerprint</dt><dd><code>${escapeHtml(finding.fingerprint)}</code></dd>
      <dt>Identities</dt><dd>${escapeHtml(finding.affectedIdentities.join(", ") || "—")}</dd>
    </dl>
    <h4>Evidence</h4><p>${escapeHtml(finding.evidence.summary)}</p>
    ${differential ? `<pre>${escapeHtml(differential)}</pre>` : ""}
    ${finding.evidence.reproduction.steps.length ? `<h4>Reproduction</h4><ol>${finding.evidence.reproduction.steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>` : ""}
    ${curls?.length ? `<pre>${escapeHtml(curls.join("\n"))}</pre>` : ""}
    <h4>Remediation</h4><p>${escapeHtml(finding.remediation.guidance)}</p>
    ${finding.remediation.codeHints?.length ? `<ul>${finding.remediation.codeHints.map((hint) => `<li>${escapeHtml(hint)}</li>`).join("")}</ul>` : ""}
    ${finding.remediation.references.length ? `<h4>References</h4><ul>${finding.remediation.references.map((reference) => `<li><code>${escapeHtml(reference)}</code></li>`).join("")}</ul>` : ""}
  </article>`;
}

function renderList(title: string, items: string[]): string {
  return items.length
    ? `<section><h2>${title}</h2><ul>${items.map((item) => `<li>${item}</li>`).join("")}</ul></section>`
    : "";
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
