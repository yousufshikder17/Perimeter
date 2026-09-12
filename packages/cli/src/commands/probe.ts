import { readFile, writeFile, mkdir, realpath, lstat } from "node:fs/promises";
import { readdir } from "node:fs/promises";
import { join, dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command, Option } from "clipanion";
import { lintFile, type LintFinding } from "@perimeter/probe-linter";

const TEMPLATES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "templates");

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
    const match = /^([a-z0-9]+(?:-[a-z0-9]+)*)\/([a-z0-9]+(?:-[a-z0-9]+)*)$/.exec(this.ref);
    const reserved = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;
    if (!match || reserved.test(match[1]!) || reserved.test(match[2]!)) {
      this.context.stderr.write("Expected exactly <family>/<name> using lowercase letters, digits and single hyphens; device names are not allowed.\n");
      return 1;
    }
    const family = match[1]!;
    const name = match[2]!;
    const assets = [["probe.template.ts", "probe.ts"], ["manifest.template.ts", "manifest.ts"],
      ["probe.test.template.ts", "probe.test.ts"], ["config.schema.template.json", "config.schema.json"]] as const;
    // Render all assets first: missing packaged templates leave no partial scaffold.
    const files: Array<{ file: string; text: string }> = await Promise.all(assets.map(async ([template, file]) => ({ file,
      text: (await readFile(join(TEMPLATES_DIR, template), "utf8")).replaceAll("__FAMILY__", family).replaceAll("__ID__", this.ref) })));
    files.push({ file: "package.json", text: JSON.stringify({ name: `perimeter-probe-${family}-${name}`, private: true, type: "module",
      scripts: { build: "tsc --target ES2022 --module NodeNext --moduleResolution NodeNext --strict --skipLibCheck --types node --outDir dist probe.ts manifest.ts probe.test.ts",
        test: "npm run build && node --test dist/probe.test.js" } }, null, 2) + "\n" });
    await mkdir(resolve(this.dir), { recursive: true });
    const root = await realpath(resolve(this.dir));
    const parent = join(root, family);
    await mkdir(parent, { recursive: true });
    if ((await lstat(parent)).isSymbolicLink() || await realpath(parent) !== parent) throw new Error("Scaffold family directory must not redirect outside its output root");
    const outDir = join(parent, name);
    await mkdir(outDir); // Exclusive ownership: never overwrite or adopt an existing scaffold.
    for (const file of files) await writeFile(join(outDir, file.file), file.text, { flag: "wx" });
    this.context.stdout.write(`Scaffolded ${outDir} (probe, manifest, schema, fixture tests and package scripts).\n`);
    this.context.stdout.write("Run the package's test script, then load its dist/probe.js using probePaths. The starter is a transport diagnostic, not a vulnerability detector.\n");
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
