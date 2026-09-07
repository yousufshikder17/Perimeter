import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { parse as parseToml } from "smol-toml";

/** Declarative config formats share the same validation after parsing. */
export async function readConfigFile(path: string): Promise<unknown> {
  const text = await readFile(path, "utf8");
  switch (extname(path).toLowerCase()) {
    case ".json": return JSON.parse(text) as unknown;
    case ".toml": return parseToml(text);
    default: return parseYaml(text) as unknown;
  }
}
