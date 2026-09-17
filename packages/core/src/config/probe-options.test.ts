import { expect, it } from "vitest";
import { parseScanConfig } from "./scan-config.js";
import { resolveProbeOptions, validateProbeOptions } from "./probe-options.js";
import type { Probe } from "@perimeter/sdk";

const probe: Probe = {
  manifest: { id: "test/options", family: "test", version: "1", schemaVersion: "1", requires: {},
    safety: { class: "read-only", destructive: false, maxRequests: 1 },
    configSchema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 3 },
      nested: { type: "object", properties: { tags: { type: "array", items: { type: "string" } } }, additionalProperties: false } }, additionalProperties: false } },
  async plan() { return { probeId: "test/options", steps: [] }; }, async run() {},
};

it("validates JSON Schema without coercion, copies and deeply freezes per-probe options", async () => {
  const input = { limit: 2, nested: { tags: ["one"] } };
  const options = await validateProbeOptions(probe, input);
  expect(options).toEqual(input); expect(options).not.toBe(input);
  expect(Object.isFrozen(options)).toBe(true);
  expect(Object.isFrozen((options.nested as typeof input.nested).tags)).toBe(true);
  input.nested.tags.push("two"); expect((options.nested as typeof input.nested).tags).toEqual(["one"]);
  for (const invalid of [{ limit: "2" }, { limit: 0 }, { limit: 4 }, { extra: "secret-canary" }, [], null]) {
    await expect(validateProbeOptions(probe, invalid)).rejects.toThrow(/^Invalid options or configuration schema for probe test\/options$/);
  }
});

it("rejects ambiguous/non-JSON/oversized options and unsafe or remote schemas", async () => {
  const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
  for (const input of [{ x: undefined }, { x: NaN }, { x: new Date() }, { x: () => 1 }, cyclic,
    { x: "x".repeat(65537) }, JSON.parse('{"__proto__":{"polluted":true}}')]) {
    await expect(validateProbeOptions(probe, input)).rejects.toThrow("Invalid options");
  }
  for (const configSchema of [{ type: "bogus" }, { $ref: "https://example.invalid/schema" },
    { $async: true, type: "object" }, "https://example.invalid/schema.json", "//example.invalid/schema.json", { type: "object", unknownKeyword: true }]) {
    await expect(validateProbeOptions({ ...probe, manifest: { ...probe.manifest, configSchema } })).rejects.toThrow("Invalid options");
  }
});

it("rejects unknown IDs, duplicate IDs and options for probes without schemas; permits legacy empty options", async () => {
  const manifest = { ...probe.manifest };
  delete manifest.configSchema;
  const legacy = { ...probe, manifest };
  expect(await validateProbeOptions(legacy)).toEqual({});
  await expect(validateProbeOptions(legacy, { extra: true })).rejects.toThrow();
  await expect(resolveProbeOptions([probe], { "test/typo": {} })).rejects.toThrow("unknown probe");
  await expect(resolveProbeOptions([probe, probe])).rejects.toThrow("unique");
  expect((await resolveProbeOptions([probe], {}, [])).size).toBe(0);
  await expect(resolveProbeOptions([probe], { "test/options": { extra: true } }, [])).rejects.toThrow();
  expect(parseScanConfig({ target: "target.json" }).probeOptions).toEqual({});
  expect(() => parseScanConfig({ target: "t", probeOptions: { test: {} } })).toThrow();
});
