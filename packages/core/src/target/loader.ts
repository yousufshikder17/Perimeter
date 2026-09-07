import { resolve, extname } from "node:path";
import { pathToFileURL } from "node:url";
import { readConfigFile } from "../config/read-file.js";
import { parseTargetModel, type TargetModel } from "@perimeter/sdk";

/**
 * Load & validate a Target Model (spec §5). Supports YAML/JSON/TOML declaratively and
 * `.ts`/`.js` modules (which must default-export a plain object). Secrets are
 * never in the file — only env refs (spec §5.1), enforced by the schema.
 */
export async function loadTargetModel(path: string): Promise<TargetModel> {
  const raw = await readContent(path);
  return parseTargetModel(raw);
}

async function readContent(path: string): Promise<unknown> {
  if ([".ts", ".js", ".mjs"].includes(extname(path).toLowerCase())) {
    const mod = (await import(pathToFileURL(resolve(path)).href)) as { default?: unknown };
    return mod.default ?? mod;
  }
  return readConfigFile(path);
}
