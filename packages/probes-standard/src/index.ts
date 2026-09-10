import type { Probe, ProbePackage } from "@perimeter/sdk";
import { crossTenantRead } from "./tenant-isolation/cross-tenant-read.js";
import { sequentialIdSwap } from "./idor/sequential-id-swap.js";
import { sqliDifferential } from "./injection/sqli-differential.js";
import { tokenManipulation } from "./auth/token-manipulation.js";
import { burstThrottle } from "./rate-limit/burst-throttle.js";
import { graphqlAuthorization } from "./graphql/authorization.js";
import { csvFormula } from "./csv/formula.js";
import { massAssignment } from "./mass-assignment/protected-field.js";

/**
 * @perimeter/probes-standard — REST families plus reviewed GraphQL authorization.
 *
 * Each is authored as a plugin on @perimeter/sdk; nothing in the engine
 * special-cases a family name. The `perimeter.probes` export is the package
 * discovery convention (spec §3.1) — the CLI loads it exactly as it would any
 * third-party family.
 */
export const STANDARD_PROBES: Probe[] = [
  crossTenantRead,
  sequentialIdSwap,
  sqliDifferential,
  tokenManipulation,
  burstThrottle,
  graphqlAuthorization,
  csvFormula,
  massAssignment,
];

export const perimeter: ProbePackage["perimeter"] = { probes: STANDARD_PROBES };

// Named exports for direct import / testing
export { crossTenantRead, sequentialIdSwap, sqliDifferential, tokenManipulation, burstThrottle, graphqlAuthorization, csvFormula, massAssignment };
