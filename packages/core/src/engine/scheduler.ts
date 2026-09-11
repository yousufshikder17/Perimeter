import type { Probe, TargetModel } from "@perimeter/sdk";

/**
 * Probe selection (spec §2.2 step 2). Matches each probe's `requires` block
 * against the Target Model capabilities. Unsatisfiable probes are returned as
 * explicit skips with reasons — never silently dropped.
 */

export interface Selection {
  applicable: Probe[];
  skipped: Array<{ probeId: string; reason: string }>;
}

export function selectProbes(
  probes: Probe[],
  target: TargetModel,
  filter: { include: string[]; exclude: string[] },
): Selection {
  const applicable: Probe[] = [];
  const skipped: Selection["skipped"] = [];

  for (const probe of probes) {
    const { id, family } = probe.manifest;

    if (filter.exclude.some((f) => id === f || family === f)) {
      skipped.push({ probeId: id, reason: `excluded by config` });
      continue;
    }
    if (filter.include.length && !filter.include.some((f) => id === f || family === f)) {
      skipped.push({ probeId: id, reason: `not in include filter` });
      continue;
    }

    const reason = unmetRequirement(probe, target);
    if (reason) {
      skipped.push({ probeId: id, reason });
      continue;
    }
    applicable.push(probe);
  }
  return { applicable, skipped };
}

/** Returns a human reason if the target can't satisfy the probe, else null. */
function unmetRequirement(probe: Probe, target: TargetModel): string | null {
  const req = probe.manifest.requires;

  if (req.minTenants && target.tenancy.tenants.length < req.minTenants) {
    return `requires ≥${req.minTenants} tenants, target models ${target.tenancy.tenants.length}`;
  }
  if (req.identities) {
    const have = new Set(target.identities.map((i) => i.ref));
    const missing = req.identities.filter((r) => !have.has(r));
    if (missing.length) return `missing identities: ${missing.join(", ")}`;
  }
  if (req.endpoints) {
    for (const cap of req.endpoints) {
      if (!target.endpoints.some((e) => endpointHasCapability(e, cap))) {
        return `no endpoint provides capability "${cap}"`;
      }
    }
  }
  return null;
}

/** Map a `requires.endpoints` capability tag to endpoint annotations (spec §5.3). */
function endpointHasCapability(
  e: TargetModel["endpoints"][number],
  cap: string,
): boolean {
  if (e.grpc) return cap === "grpcUnary";
  if (e.graphql) return cap === "graphqlQuery";
  switch (cap) {
    case "massAssignment":
      return e.massAssignment !== undefined;
    case "csvExport":
      return e.csv !== undefined;
    case "readsTenantScopedObject":
      return e.tenantScoped && e.method === "GET";
    case "createsObject":
      return e.creates !== undefined;
    case "rateSensitive":
      return e.rateSensitive;
    case "injectableInput":
      return (e.injectable?.length ?? 0) > 0;
    case "authRequired":
      return e.auth === "required";
    case "hasObjectRef":
      return e.objectRef !== undefined;
    default:
      return false;
  }
}
