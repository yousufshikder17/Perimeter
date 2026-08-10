import { readFile, writeFile } from "node:fs/promises";
import { Command, Option } from "clipanion";
import { FindingRegistrySchema } from "@perimeter/sdk";
import { MarkdownReporter, SarifReporter, JUnitReporter, JsonReporter } from "@perimeter/core";

/**
 * `perimeter report <findings.json> --format <fmt>` (spec §6.5). Re-renders a
 * previously-produced finding registry into another format without re-scanning —
 * useful for generating SARIF/JUnit from an archived scan.
 */
export class ReportCommand extends Command {
  static override paths = [["report"]];
  static override usage = Command.Usage({ description: "Render a finding registry into another format." });

  input = Option.String({ required: true });
  format = Option.String("--format", "markdown", { description: "markdown|json|sarif|junit" });
  out = Option.String("--out", { description: "Output file (default stdout)." });

  async execute(): Promise<number> {
    const registry = FindingRegistrySchema.parse(JSON.parse(await readFile(this.input, "utf8")));
    const reporter = {
      markdown: new MarkdownReporter(),
      json: new JsonReporter(),
      sarif: new SarifReporter(),
      junit: new JUnitReporter(),
    }[this.format];
    if (!reporter) {
      this.context.stderr.write(`✗ unknown format "${this.format}"\n`);
      return 1;
    }
    const rendered = reporter.render(registry);
    if (this.out) await writeFile(this.out, rendered);
    else this.context.stdout.write(rendered);
    return 0;
  }
}
