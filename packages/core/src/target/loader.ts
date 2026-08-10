import { readFile } from "node:fs/promises";
import { parse as parseYaml } from "yaml";
import { parseTargetModel, type TargetModel } from "@perimeter/sdk";

/**
 * Load & validate a Target Model (spec §5). Supports YAML/JSON declaratively and
 * `.ts`/`.js` modules (which must default-export a plain object). Secrets are
 * never in the file — only env refs (spec §5.1), enforced by the schema.
 */
export async function loadTargetModel(path: string): Promise<TargetModel> {
  const raw = await readContent(path);
  return parseTargetModel(raw);
}

async function readContent(path: string): Promise<unknown> {
  if (path.endsWith(".ts") || path.endsWith(".js") || path.endsWith(".mjs")) {
    const mod = (await import(pathToFileUrl(path))) as { default?: unknown };
    return mod.default ?? mod;
  }
  const text = await readFile(path, "utf8");
  if (path.endsWith(".json")) return JSON.parse(text);
  // YAML parser also accepts JSON and (loosely) handles TOML-free configs.
  return parseYaml(text);
}

function pathToFileUrl(p: string): string {
  const abs = p.replace(/\\/g, "/");
  return abs.startsWith("file:") ? abs : `file://${abs.startsWith("/") ? "" : "/"}${abs}`;
}
