import { writeFile } from "node:fs/promises";
import { Command, Option } from "clipanion";
import { stringify as toYaml } from "yaml";
import {
  loadTargetModel,
  discoverFromHar,
  discoverFromOpenApi,
  discoverFromPostman,
  discoverFromCrawl,
} from "@perimeter/core";

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

export class ModelCrawlCommand extends Command {
  static override paths = [["model", "crawl"]];
  static override usage = Command.Usage({ description: "Discover a draft GET inventory using an authorized Target Model and identity." });

  target = Option.String({ required: true });
  as = Option.String("--as", { required: true, description: "Configured identity reference." });
  start = Option.String("--start", "/");
  maxPages = Option.String("--max-pages", "50");
  maxDepth = Option.String("--max-depth", "3");
  maxSeconds = Option.String("--max-seconds", "120");
  auditLog = Option.String("--audit-log", "crawl-audit.ndjson");
  out = Option.String("--out", { description: "Create a draft YAML file (never overwrites)." });

  async execute(): Promise<number> {
    const result = await discoverFromCrawl(this.target, {
      as: this.as, start: this.start, maxPages: Number(this.maxPages), maxDepth: Number(this.maxDepth),
      maxWallClockSeconds: Number(this.maxSeconds), auditLog: this.auditLog,
    });
    const yaml = toYaml({ endpoints: result.endpoints });
    if (this.out) await writeFile(this.out, yaml, { flag: "wx" });
    else this.context.stdout.write(yaml);
    this.context.stderr.write("Review required:\n" + result.reviewNotes.map((note) => `  - ${note}\n`).join(""));
    return 0;
  }
}

export class ModelDiscoverCommand extends Command {
  static override paths = [["model", "discover"]];
  static override usage = Command.Usage({
    description: "Bootstrap a draft endpoint inventory from OpenAPI, Postman, or HAR (spec §5.4).",
  });

  spec = Option.String({ required: true });
  source = Option.String("--from", "openapi", { description: "openapi|postman|har" });
  out = Option.String("--out", { description: "Write the draft inventory YAML here." });

  async execute(): Promise<number> {
    if (this.source !== "openapi" && this.source !== "postman" && this.source !== "har") {
      this.context.stderr.write(`Unsupported discovery source: ${this.source}\n`);
      return 1;
    }
    const result = await (this.source === "postman"
      ? discoverFromPostman(this.spec)
      : this.source === "har"
        ? discoverFromHar(this.spec)
        : discoverFromOpenApi(this.spec));
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
