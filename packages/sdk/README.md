# @perimeter/sdk

The probe SDK for [Perimeter](../../README.md). This package is the stable
surface that extension packages may depend on; engine internals are not exposed.

## Exports

| Import | Contents |
|---|---|
| `@perimeter/sdk` | Everything below, re-exported. |
| `@perimeter/sdk` → `Probe`, `ProbeContext`, `ProbePlan`, `Skip` | The probe lifecycle contract (spec §3.2). |
| `@perimeter/sdk/manifest` | `ProbeManifest`, `ProbeFamily`, `SafetyClass`, Zod schemas (spec §3.1). |
| `@perimeter/sdk/finding` | `Finding`, `Evidence`, `Remediation`, `Pass`, `FindingRegistry` (spec §6). |
| `@perimeter/sdk/target-model` | `TargetModel`, `Endpoint`, `Authorization`, `Tenancy` (spec §5). |

## Writing a probe

```ts
import { type Probe, skip } from "@perimeter/sdk";

export const myProbe: Probe = {
  manifest: {
    id: "tenant-isolation/my-check",
    family: "tenant-isolation",
    version: "0.1.0",
    schemaVersion: "1",
    requires: { minTenants: 2, identities: ["tenantA.user", "tenantB.user"] },
    safety: { class: "read-only", maxRequests: 25, destructive: false },
  },
  async plan(ctx) {
    if (ctx.target.tenancy.tenants.length < 2) return skip("needs ≥2 tenants");
    return { probeId: this.manifest.id, steps: [/* ... */] };
  },
  async run(plan, ctx) {
    // All egress via ctx.http — never `fetch`. Evidence is mandatory on findings.
  },
};
```

See the [Probe Authoring Guide](../../docs/authoring/README.md) for the full
safety contract and the "good probe" rubric.
