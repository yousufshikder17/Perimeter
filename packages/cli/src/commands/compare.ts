import { readFile, writeFile } from "node:fs/promises";
import { Command, Option } from "clipanion";
import { FindingRegistrySchema, type Severity } from "@perimeter/sdk";
import {
  compareScans,
  renderComparisonHtml,
  renderComparisonJson,
  renderComparisonMarkdown,
} from "@perimeter/core";

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export class CompareCommand extends Command {
  static override paths = [["compare"]];
  static override usage = Command.Usage({
    description: "Compare two scan artifacts by stable finding fingerprint.",
  });

  previous = Option.String({ required: true });
  current = Option.String({ required: true });
  format = Option.String("--format", "markdown", { description: "markdown|html|json" });
  out = Option.String("--out", { description: "Output file (default stdout)." });
  failOn = Option.String("--fail-on", "none", {
    description: "Fail on new open findings at CRITICAL|HIGH|MEDIUM|LOW|INFO|none.",
  });

  async execute(): Promise<number> {
    const previous = FindingRegistrySchema.parse(JSON.parse(await readFile(this.previous, "utf8")));
    const current = FindingRegistrySchema.parse(JSON.parse(await readFile(this.current, "utf8")));
    const comparison = compareScans(previous, current);
    const renderers: Record<string, typeof renderComparisonJson> = {
      markdown: renderComparisonMarkdown,
      html: renderComparisonHtml,
      json: renderComparisonJson,
    };
    const rendered = renderers[this.format]?.(comparison);

    if (!rendered) {
      this.context.stderr.write(`unknown comparison format "${this.format}"\n`);
      return 1;
    }
    if (this.out) await writeFile(this.out, rendered);
    else this.context.stdout.write(rendered);

    if (this.failOn === "none") return 0;
    const threshold = SEVERITY_RANK[this.failOn as Severity];
    if (!threshold) {
      this.context.stderr.write(`unknown severity "${this.failOn}"\n`);
      return 1;
    }
    const gating = comparison.newFindings.filter(
      (finding) => finding.status === "open" && SEVERITY_RANK[finding.severity] >= threshold,
    );
    if (gating.length) {
      this.context.stderr.write(
        `comparison gate failed: ${gating.length} new open finding(s) at ≥${this.failOn}\n`,
      );
      return 1;
    }
    return 0;
  }
}
