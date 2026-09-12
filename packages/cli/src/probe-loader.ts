import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
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
    if (mod.perimeter?.probes) probes.push(...mod.perimeter.probes);
    else if (mod.STANDARD_PROBES) probes.push(...mod.STANDARD_PROBES);
  }
  return probes;
}
