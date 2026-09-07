import { Builtins, Cli } from "clipanion";
import { ScanCommand } from "./commands/scan.js";
import { ModelValidateCommand, ModelDiscoverCommand, ModelCrawlCommand } from "./commands/model.js";
import { ProbeNewCommand, ProbeLintCommand } from "./commands/probe.js";
import { ReportCommand } from "./commands/report.js";
import { BaselineCreateCommand } from "./commands/baseline.js";
import { CompareCommand } from "./commands/compare.js";

/** Build the Perimeter CLI (spec §9: scan / model / probe new / report). */
export function buildCli(): Cli {
  const cli = new Cli({
    binaryLabel: "Perimeter",
    binaryName: "perimeter",
    binaryVersion: "0.1.0",
  });
  cli.register(ScanCommand);
  cli.register(ModelValidateCommand);
  cli.register(ModelDiscoverCommand);
  cli.register(ModelCrawlCommand);
  cli.register(ProbeNewCommand);
  cli.register(ProbeLintCommand);
  cli.register(ReportCommand);
  cli.register(BaselineCreateCommand);
  cli.register(CompareCommand);
  cli.register(Builtins.HelpCommand);
  cli.register(Builtins.VersionCommand);
  return cli;
}
