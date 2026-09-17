import { readFile } from "node:fs/promises";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { Probe } from "@perimeter/sdk";

export class ProbeOptionsError extends Error {}

/** Bound JSON input and reject values that change meaning when sent to a worker. */
function jsonCopy(value: unknown): unknown {
  let nodes = 0;
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > 10000 || depth > 16) throw new Error("JSON limit");
    if (item === null || typeof item === "boolean" || typeof item === "string") return;
    if (typeof item === "number" && Number.isFinite(item)) return;
    if (typeof item !== "object" || (!Array.isArray(item) && Object.getPrototypeOf(item) !== Object.prototype && Object.getPrototypeOf(item) !== null)) throw new Error("Not JSON");
    if (Array.isArray(item) && Object.keys(item).length !== item.length) throw new Error("Sparse or decorated array");
    for (const [key, child] of Object.entries(item)) {
      if (["__proto__", "constructor", "prototype"].includes(key)) throw new Error("Unsafe key");
      visit(child, depth + 1);
    }
  };
  visit(value, 0);
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text) > 65536) throw new Error("JSON limit");
  return JSON.parse(text);
}

function freeze(value: unknown): void {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
}

/** Shared by the engine and fixture harness. Errors never echo options/schema contents. */
export async function validateProbeOptions(probe: Probe, input: unknown = {}): Promise<Readonly<Record<string, unknown>>> {
  try {
    const options = jsonCopy(input) as Record<string, unknown>;
    if (!options || Array.isArray(options) || typeof options !== "object") throw new Error("Expected object");
    const declared = probe.manifest.configSchema;
    let schema: unknown = declared;
    if (typeof declared === "string") {
      // CLI resolves package-relative paths; programmatic callers use cwd-relative files.
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(declared)) throw new Error("Local schemas only");
      const file = await readFile(declared);
      if (file.length > 65536) throw new Error("Schema limit");
      schema = JSON.parse(file.toString("utf8"));
    }
    schema ??= { type: "object", properties: {}, additionalProperties: false };
    if ((schema as Record<string, unknown>).$async) throw new Error("Synchronous schemas only");
    // No async loading, custom keywords, coercion, default insertion or field removal.
    const ajv = new Ajv2020({ strict: true, allErrors: false, ownProperties: true, logger: false });
    const validate = ajv.compile(jsonCopy(schema) as Record<string, unknown>);
    if (!validate(options)) throw new Error("Invalid options");
    freeze(options);
    return options;
  } catch {
    throw new ProbeOptionsError(`Invalid options or configuration schema for probe ${probe.manifest.id}`);
  }
}

/** Unknown keys and duplicate IDs fail closed, even when a probe is excluded. */
export async function resolveProbeOptions(probes: Probe[], input: Record<string, unknown> = {}, selected: Probe[] = probes) {
  const installed = new Map(probes.map(probe => [probe.manifest.id, probe]));
  if (installed.size !== probes.length) throw new ProbeOptionsError("Probe IDs must be unique");
  for (const id of Object.keys(input)) {
    if (!installed.has(id)) throw new ProbeOptionsError("Options reference an unknown probe ID");
  }
  const options = new Map<string, Readonly<Record<string, unknown>>>();
  for (const probe of probes) {
    if (selected.includes(probe) || Object.hasOwn(input, probe.manifest.id)) {
      options.set(probe.manifest.id, await validateProbeOptions(probe, input[probe.manifest.id]));
    }
  }
  return options;
}
