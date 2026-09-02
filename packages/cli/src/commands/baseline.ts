import { readFile, writeFile } from "node:fs/promises";
import { Command, Option } from "clipanion";
import { FindingRegistrySchema } from "@perimeter/sdk";
import { createBaselineFile } from "@perimeter/core";

export class BaselineCreateCommand extends Command {
  static override paths = [["baseline", "create"]];
  static override usage = Command.Usage({
    description: "Create a reviewed-findings baseline from a scan artifact.",
  });

  input = Option.String({ required: true });
  out = Option.String("--out", "perimeter-baseline.json", { description: "Baseline output path." });
  acceptCurrent = Option.Boolean("--accept-current", false, {
    description: "Explicitly acknowledge every current finding as accepted.",
  });

  async execute(): Promise<number> {
    if (!this.acceptCurrent) {
      this.context.stderr.write(
        "Refusing to suppress findings without --accept-current. Review the scan artifact first.\n",
      );
      return 1;
    }

    const registry = FindingRegistrySchema.parse(JSON.parse(await readFile(this.input, "utf8")));
    const baseline = createBaselineFile(registry);
    await writeFile(this.out, JSON.stringify(baseline, null, 2) + "\n", { flag: "wx" });
    this.context.stdout.write(
      `baseline → ${this.out} (${baseline.acceptedFingerprints.length} accepted fingerprint(s))\n`,
    );
    return 0;
  }
}
