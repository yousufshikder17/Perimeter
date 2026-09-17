import { pathToFileURL, fileURLToPath } from "node:url";
import { resolve, dirname, isAbsolute } from "node:path";
import { access, readFile } from "node:fs/promises";
import type { Probe, ProbePackage } from "@perimeter/sdk";
import { STANDARD_PROBES } from "@perimeter/probes-standard";

/**
 * Load probes for a scan: the standard library plus any package/dir declaring a
 * `perimeter.probes` export (spec §3.1). Third-party families load identically —
 * nothing special-cases them.
 */
export async function loadProbes(extraPaths: string[]): Promise<Probe[]> {
  const probes: Probe[] = [...STANDARD_PROBES];
  for (const p of extraPaths) {
    const packageName = /^(?:@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/i.test(p);
    const url = packageName ? p : pathToFileURL(resolve(p)).href;
    const mod = (await import(url)) as Partial<ProbePackage> & { STANDARD_PROBES?: Probe[] };
    const loaded = mod.perimeter?.probes ?? mod.STANDARD_PROBES ?? [];
    for (const probe of loaded) {
      if (typeof probe.manifest.configSchema !== "string") { probes.push(probe); continue; }
      try {
        const schemaPath = probe.manifest.configSchema;
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(schemaPath)) throw new Error("Local schemas only");
        const moduleDirectory = dirname(fileURLToPath(packageName ? import.meta.resolve(p) : url));
        let root = moduleDirectory;
        while (true) {
          if (await access(resolve(root, "package.json")).then(() => true, () => false)) break;
          if (dirname(root) === root) { root = moduleDirectory; break; }
          root = dirname(root);
        }
        const file = await readFile(isAbsolute(schemaPath) ? schemaPath : resolve(root, schemaPath));
        if (file.length > 65536) throw new Error("Schema limit");
        const configSchema: unknown = JSON.parse(file.toString("utf8"));
        if (!configSchema || typeof configSchema !== "object" || Array.isArray(configSchema)) throw new Error("Expected schema object");
        probes.push({ ...probe, manifest: { ...probe.manifest, configSchema: configSchema as Record<string, unknown> } });
      } catch {
        throw new Error(`Cannot load local configuration schema for probe ${probe.manifest.id}`);
      }
    }
  }
  return probes;
}
