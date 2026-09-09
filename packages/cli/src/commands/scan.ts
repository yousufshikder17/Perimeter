import { writeFile } from "node:fs/promises";
import { Command, Option } from "clipanion";
import {
  Orchestrator,
  parseScanConfig,
  readConfigFile,
  JsonReporter,
  MarkdownReporter,
  HtmlReporter,
  SarifReporter,
  JUnitReporter,
  loadBaseline,
  createIsolatedProbe,
} from "@perimeter/core";
import type { FindingRegistry, Severity } from "@perimeter/sdk";
import { loadProbes } from "../probe-loader.js";

/**
 * `perimeter scan --config target.yaml` (spec §8 acceptance scenario).
 *
 * Runs all applicable probes under the authorized rate cap, writes the report
 * artifacts, and exits non-zero if any finding at/above the gate severity
 * remains open after baseline suppression (the CI gate, spec §8.6).
 */
export class ScanCommand extends Command {
  static override paths = [["scan"]];
  static override usage = Command.Usage({
    description: "Run an adversarial scan against a modeled target.",
    examples: [["Scan a staging target", "perimeter scan --config target.yaml"]],
  });

  config = Option.String("--config", {
    required: true,
    description: "Path to the scan config (YAML/JSON/TOML).",
  });
  failOn = Option.String("--fail-on", {
    description: "Gate severity: CRITICAL|HIGH|MEDIUM|LOW|INFO|none.",
  });
  seed = Option.String("--seed", { description: "Deterministic seed (overrides config)." });
  resume = Option.Boolean("--resume", false, { description: "Resume the explicitly configured checkpoint." });
  allowMutating = Option.Boolean("--allow-mutating", false, {
    description: "Permit idempotent-write/mutating probes (default off).",
  });

  async execute(): Promise<number> {
    const raw = parseScanConfig(await readConfigFile(this.config));
    const config = parseScanConfig({
      ...raw,
      ...(this.failOn ? { failOn: this.failOn } : {}),
      ...(this.seed ? { seed: this.seed } : {}),
      ...(this.resume ? { resume: true } : {}),
      ...(this.allowMutating ? { allowMutating: true } : {}),
    });

    const probes = await loadProbes(config.probePaths);
    probes.push(...config.isolatedProbes.map(createIsolatedProbe));
    const baseline = config.baseline ? await loadBaseline(config.baseline) : undefined;

    const registry = await new Orchestrator(config, probes, baseline ? { baseline } : {}).run();
    await this.#writeReports(config, registry);

    const gate = decideGate(registry, config.failOn as Severity | "none");
    if (gate.failed) {
      this.context.stderr.write(`\n✗ gate failed: ${gate.reason}\n`);
      return 1;
    }
    this.context.stdout.write(
      `\n✓ scan complete — ${registry.findings.length} finding(s), gate passed\n`,
    );
    return 0;
  }

  async #writeReports(
    config: { output: NonNullable<ReturnType<typeof parseScanConfig>["output"]> },
    registry: FindingRegistry,
  ): Promise<void> {
    const { output } = config;
    await writeFile(output.json, new JsonReporter().render(registry));
    await writeFile(output.markdown, new MarkdownReporter().render(registry));
    if (output.html) await writeFile(output.html, new HtmlReporter().render(registry));
    if (output.sarif) await writeFile(output.sarif, new SarifReporter().render(registry));
    if (output.junit) await writeFile(output.junit, new JUnitReporter().render(registry));
    this.context.stdout.write(`report → ${output.markdown}, findings → ${output.json}\n`);
  }
}

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

function decideGate(
  registry: FindingRegistry,
  failOn: Severity | "none",
): { failed: boolean; reason: string } {
  if (failOn === "none") return { failed: false, reason: "gating disabled" };
  const threshold = SEVERITY_RANK[failOn];
  const gating = registry.findings.filter(
    (f) => f.status === "open" && SEVERITY_RANK[f.severity] >= threshold,
  );
  return gating.length
    ? { failed: true, reason: `${gating.length} open finding(s) at ≥${failOn}` }
    : { failed: false, reason: "no gating findings" };
}
