/**
 * @perimeter/sdk — the stable probe SDK.
 *
 * Extension packages depend on this surface for the probe contract, finding
 * schema, Target Model, and runtime context types. Engine internals remain
 * private to the core package.
 */

export const SDK_VERSION = "0.1.0" as const;

// Probe contract & lifecycle
export * from "./probe.js";
export * from "./context.js";

// Static manifest & families
export * from "./manifest.js";

// Finding schema, evidence, remediation
export * from "./finding.js";

// Target Model
export * from "./target-model.js";
