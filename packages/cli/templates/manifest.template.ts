import type { ProbeManifest } from "@perimeter/sdk";

/** Pure data. Config schema is relative to this scaffold's package root. */
export const manifest: ProbeManifest = {
  id: "__ID__", family: "__FAMILY__", version: "0.1.0", schemaVersion: "1",
  requires: {}, safety: { class: "read-only", maxRequests: 1, destructive: false },
  configSchema: "config.schema.json",
};
