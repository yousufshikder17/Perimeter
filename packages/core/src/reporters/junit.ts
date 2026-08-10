import type { FindingRegistry } from "@perimeter/sdk";
import type { Reporter } from "./index.js";

/**
 * JUnit XML reporter (spec §6.5, optional) — lets generic CI dashboards surface
 * probe pass/fail. Each probe outcome is a testcase; findings become failures,
 * passes become green, skips become skipped.
 */
export class JUnitReporter implements Reporter {
  readonly name = "junit";
  readonly extension = "xml";

  render(r: FindingRegistry): string {
    const cases: string[] = [];

    for (const f of r.findings) {
      cases.push(
        `    <testcase classname="${esc(f.family)}" name="${esc(f.probeId)}: ${esc(f.title)}">`,
        `      <failure type="${esc(f.severity)}" message="${esc(f.evidence.summary)}">${esc(
          f.remediation.guidance,
        )}</failure>`,
        `    </testcase>`,
      );
    }
    for (const p of r.passes) {
      cases.push(`    <testcase classname="${esc(p.family)}" name="${esc(p.title)}"/>`);
    }
    for (const s of r.skipped) {
      cases.push(
        `    <testcase classname="skipped" name="${esc(s.probeId)}"><skipped message="${esc(
          s.reason,
        )}"/></testcase>`,
      );
    }

    const tests = r.findings.length + r.passes.length + r.skipped.length;
    return [
      `<?xml version="1.0" encoding="UTF-8"?>`,
      `<testsuites name="perimeter" tests="${tests}" failures="${r.findings.length}" skipped="${r.skipped.length}">`,
      `  <testsuite name="${esc(r.target)}" tests="${tests}" failures="${r.findings.length}" skipped="${r.skipped.length}">`,
      ...cases,
      `  </testsuite>`,
      `</testsuites>`,
      ``,
    ].join("\n");
  }
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
