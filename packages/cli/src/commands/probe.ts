import { readFile, writeFile, mkdir } from "node:fs/promises";
import { readdir } from "node:fs/promises";
import { join, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { Command, Option } from "clipanion";
import { lintFile, type LintFinding } from "@perimeter/probe-linter";

const TEMPLATES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "templates");

/**
 * `perimeter probe new <family>/<name>` (spec §3.4). Scaffolds a typed probe, a
 * manifest, a config schema, and a fixture-backed test — so authoring requires
 * understanding the vulnerability, not the engine.
 */
export class ProbeNewCommand extends Command {
  static override paths = [["probe", "new"]];
  static override usage = Command.Usage({
    description: "Scaffold a new probe from templates.",
    examples: [["Scaffold a tenant-isolation probe", "perimeter probe new tenant-isolation/my-check"]],
  });

  ref = Option.String({ required: true });
  dir = Option.String("--dir", "probes", { description: "Where to scaffold (default ./probes)." });

  async execute(): Promise<number> {
    const [family, name] = this.ref.split("/");
    if (!family || !name) {
      this.context.stderr.write(`✗ expected <family>/<name>, got "${this.ref}"\n`);
      return 1;
    }
    const outDir = join(this.dir, family);
    await mkdir(outDir, { recursive: true });

    const template = await readFile(join(TEMPLATES_DIR, "probe.template.ts"), "utf8");
    const rendered = template
      .replaceAll("__FAMILY__", family)
      .replaceAll("__NAME__", name)
      .replaceAll("__ID__", `${family}/${name}`)
      .replaceAll("__CAMEL__", toCamel(name));

    const probeFile = join(outDir, `${name}.ts`);
    await writeFile(probeFile, rendered);
    this.context.stdout.write(`✓ scaffolded ${probeFile}\n`);
    this.context.stdout.write(`  next: implement plan()/run(), add vulnerable+patched fixtures, then \`perimeter probe lint\`\n`);
    return 0;
  }
}

/**
 * `perimeter probe lint <path>` (spec §3.4). Runs the static safety linter over
 * probe sources: no raw egress, deterministic RNG, evidence-on-finding. A
 * violation is release-blocking (spec §10 risk 1).
 */
export class ProbeLintCommand extends Command {
  static override paths = [["probe", "lint"]];
  static override usage = Command.Usage({ description: "Lint probe sources against the §3.2 safety contract." });

  probePath = Option.String({ required: true });

  async execute(): Promise<number> {
    const files = await collectTsFiles(this.probePath);
    const all: LintFinding[] = [];
    for (const f of files) all.push(...(await lintFile(f)));

    for (const finding of all) {
      const stream = finding.severity === "error" ? this.context.stderr : this.context.stdout;
      stream.write(`${finding.severity === "error" ? "✗" : "⚠"} ${finding.file}:${finding.line} [${finding.rule}] ${finding.message}\n`);
    }
    const errors = all.filter((f) => f.severity === "error");
    if (errors.length) {
      this.context.stderr.write(`\n${errors.length} error(s) — probe lint failed\n`);
      return 1;
    }
    this.context.stdout.write(`✓ probe lint passed (${files.length} file(s))\n`);
    return 0;
  }
}

function toCamel(s: string): string {
  return s.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
}

async function collectTsFiles(path: string): Promise<string[]> {
  if (extname(path) === ".ts") return [path];
  const out: string[] = [];
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const full = join(path, entry.name);
    if (entry.isDirectory()) out.push(...(await collectTsFiles(full)));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) out.push(full);
  }
  return out;
}
