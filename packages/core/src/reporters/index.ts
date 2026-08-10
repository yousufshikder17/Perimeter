import type { FindingRegistry } from "@perimeter/sdk";

/**
 * Reporter contract (spec §6.5). Reporters render the finding registry into an
 * output artifact. All formats are open (no lock-in via output — spec §7.2).
 */
export interface Reporter {
  readonly name: string;
  readonly extension: string;
  render(registry: FindingRegistry): string;
}

export { JsonReporter } from "./json.js";
export { MarkdownReporter } from "./markdown.js";
export { SarifReporter } from "./sarif.js";
export { JUnitReporter } from "./junit.js";
