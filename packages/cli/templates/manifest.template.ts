import type { ProbeManifest } from "@perimeter/sdk";
import configSchema from "./config.schema.json" with { type: "json" };

/** Pure data. The build bundles the JSON schema alongside this manifest. */
export const manifest: ProbeManifest = {
  id: "__ID__", family: "__FAMILY__", version: "0.1.0", schemaVersion: "1",
  requires: {}, safety: { class: "read-only", maxRequests: 1, destructive: false },
  configSchema,
};
