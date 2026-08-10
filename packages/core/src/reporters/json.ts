import type { FindingRegistry } from "@perimeter/sdk";
import type { Reporter } from "./index.js";

/** JSON reporter (spec §6.5) — the full registry, the machine contract. */
export class JsonReporter implements Reporter {
  readonly name = "json";
  readonly extension = "json";
  render(registry: FindingRegistry): string {
    return JSON.stringify(registry, null, 2) + "\n";
  }
}
