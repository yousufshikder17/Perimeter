import { describe, expect, it } from "vitest";
import type { Finding, FindingRegistry } from "@perimeter/sdk";
import { compareScans, renderComparisonHtml, renderComparisonMarkdown } from "./comparison.js";

const finding = (fingerprint: string, title = fingerprint) =>
  ({
    fingerprint,
    title,
    severity: "HIGH",
    status: "open",
    target: { method: "GET", path: `/objects/${fingerprint}` },
  }) as Finding;

const registry = (scanId: string, findings: Finding[], target = "staging") =>
  ({ scanId, findings, target }) as FindingRegistry;

describe("scan comparison", () => {
  it("classifies unique fingerprints, renders safely, and rejects different targets", () => {
    const comparison = compareScans(
      registry("previous", [finding("same"), finding("resolved")]),
      registry("current", [finding("same"), finding("new", "New <script>finding")]),
    );

    expect(comparison.newFindings.map((item) => item.fingerprint)).toEqual(["new"]);
    expect(comparison.unchangedFindings.map((item) => item.fingerprint)).toEqual(["same"]);
    expect(comparison.resolvedFindings.map((item) => item.fingerprint)).toEqual(["resolved"]);
    expect(renderComparisonMarkdown(comparison)).toContain("| 1 | 1 | 1 |");
    expect(renderComparisonHtml(comparison)).toContain("New &lt;script&gt;finding");
    expect(() => compareScans(registry("one", [], "one"), registry("two", [], "two"))).toThrow(
      "cannot compare different targets",
    );
  });
});
