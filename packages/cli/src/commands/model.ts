import { writeFile } from "node:fs/promises";
import { Command, Option } from "clipanion";
import { stringify as toYaml } from "yaml";
import { loadTargetModel, discoverFromOpenApi } from "@perimeter/core";

/**
 * `perimeter model validate <file>` and `perimeter model discover <openapi>`
 * (spec §5, §5.4). Validation surfaces schema errors early; discovery bootstraps
 * a *draft* inventory the user reviews — ownership semantics are never guessed
 * silently.
 */
export class ModelValidateCommand extends Command {
  static override paths = [["model", "validate"]];
  static override usage = Command.Usage({ description: "Validate a Target Model file." });

  file = Option.String({ required: true });

  async execute(): Promise<number> {
    try {
      const model = await loadTargetModel(this.file);
      this.context.stdout.write(
        `✓ valid — "${model.name}": ${model.identities.length} identities, ${model.tenancy.tenants.length} tenants, ${model.endpoints.length} endpoints\n`,
      );
      return 0;
    } catch (err) {
      this.context.stderr.write(`✗ invalid Target Model:\n${String(err)}\n`);
      return 1;
    }
  }
}

export class ModelDiscoverCommand extends Command {
  static override paths = [["model", "discover"]];
  static override usage = Command.Usage({
    description: "Bootstrap a draft endpoint inventory from an OpenAPI spec (spec §5.4).",
  });

  spec = Option.String({ required: true });
  out = Option.String("--out", { description: "Write the draft inventory YAML here." });

  async execute(): Promise<number> {
    const result = await discoverFromOpenApi(this.spec);
    const yaml = toYaml({ endpoints: result.endpoints });
    if (this.out) {
      await writeFile(this.out, yaml);
      this.context.stdout.write(`draft inventory → ${this.out}\n`);
    } else {
      this.context.stdout.write(yaml + "\n");
    }
    if (result.reviewNotes.length) {
      this.context.stdout.write(`\n⚠ Review required before trusting this model:\n`);
      for (const note of result.reviewNotes) this.context.stdout.write(`  - ${note}\n`);
    }
    return 0;
  }
}
