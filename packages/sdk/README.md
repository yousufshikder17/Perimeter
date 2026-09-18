# @perimeter/sdk

The probe SDK for [Perimeter](../../README.md). This package is the public
extension surface; engine internals are not part of its compatibility contract.

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

## Compatibility coverage

After building, run `pnpm test tests/e2e/sdk-compatibility.test.ts`. This also
runs in the normal CI suite, in both editions. It requires the existing pnpm
toolchain and `tar`, but no external application, registry access or credentials.

A hand-written consumer is copied outside the workspace, compiled in strict
NodeNext mode against an actual SDK package archive, and run with its own copy
of the SDK's declared dependencies. The check covers root/documented subpath
imports, shipped declarations, re-exports, negative type/import contracts, and
pass/finding/skip lifecycle behavior. It exercises options through the fixture
harness and loads the scoped external package through the built CLI against a
loopback fixture, checking gate results and captured evidence. Removing a shipped
declaration must make the consumer build fail. The host runtime still uses its
normal dependencies; the external consumer imports no core internals.

This is a regression contract for the currently exercised ESM/TypeScript API,
not SDK v1 certification or proof that every export, compiler, Node release or
third-party plugin is compatible. CommonJS and browser bundlers are not covered.
Add representative consumer cases when extending the supported surface. Do not
regenerate or weaken the fixture merely to make an incompatible change pass;
review the change and document migration/versioning before release. Real-team
adoption and broader runtime/version matrices remain separate validation work.
