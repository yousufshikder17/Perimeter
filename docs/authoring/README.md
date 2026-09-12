# Probe Authoring Guide

The probe library is the moat (spec §3). This guide is the contract you author
against — read it before writing a probe. If you understand *the vulnerability*,
the engine takes care of the rest.

## The one contract

Every probe — the five standard families and yours — implements the same
lifecycle (spec §3.2):

```ts
interface Probe {
  readonly manifest: ProbeManifest;                    // static identity + requirements
  plan(ctx): Promise<ProbePlan | Skip>;                // decide applicability; NO network
  run(plan, ctx): Promise<void>;                       // execute; emit findings/passes
}
```

`plan()` decides whether the probe applies to the modeled target and, if so,
returns the concrete steps it intends to run. **It must not issue any network
request.** `run()` executes those steps — all egress via `ctx.http`.

## The safety contract (non-negotiable)

These are enforced by the engine at runtime and by `perimeter probe lint`
statically (spec §3.2, §3.4). You cannot ship a probe that violates them.

1. **No raw network.** A probe cannot `fetch` or import `node:http`/`undici`.
   The only egress is `ctx.http` — rate-limited, host-allow-listed, verb-policed,
   audited. `ProbeContext` deliberately exposes no raw network.
2. **Read-only by default.** `ctx.http` refuses `POST/PUT/PATCH/DELETE` unless
   your manifest's `safety.class` permits it *and* the scan authorized it — and
   even then, writes must hit engine-created **scratch objects**, never real data.
   Standard mass-assignment and webhook checks require explicit write opt-in;
   they still target engine-created scratch records only.
3. **Evidence is mandatory.** `ctx.report(finding)` rejects a finding with no
   `Evidence` bundle. No evidence, no finding.
4. **Determinism.** All randomness via `ctx.rng`; all time via `ctx.clock`. Never
   `Math.random()` or `Date.now()` for control flow — a finding must reproduce
   from the recorded seed.
5. **Cooperative cancellation & budgets.** Await against `ctx.signal`; stop when
   `ctx.budget` is exhausted. The engine can halt a scan instantly.

## The manifest (spec §3.1)

```jsonc
{
  "id": "idor/sequential-id-swap",   // "<family>/<name>"
  "family": "idor",
  "version": "0.1.0",
  "schemaVersion": "1",              // finding-schema major you emit
  "requires": {                      // what the Target Model must satisfy
    "identities": ["tenantA.user"],
    "endpoints": ["hasObjectRef", "authRequired"]
  },
  "safety": { "class": "read-only", "maxRequests": 30, "destructive": false }
}
```

`requires.endpoints` capability tags (matched against Target Model annotations,
spec §5.3): `readsTenantScopedObject`, `createsObject`, `rateSensitive`,
`injectableInput`, `authRequired`, `hasObjectRef`, `roleAccess`, `graphqlQuery`,
`grpcUnary`, `csvExport`, `massAssignment`, `webhookCallback`.

## The "good probe" rubric

A finding a developer can't act on is a bug in the probe. Aim for:

- **High signal.** Prefer CONFIRMED over TENTATIVE. Distinguish a 404-by-design
  from a 200-leak. False positives erode trust faster than missed findings.
- **Minimal requests.** Prove the boundary with the fewest exchanges. Respect the
  budget; the smallest evidence that proves the point is the best evidence.
- **Clear remediation.** Author concrete, class-specific guidance (spec §6.4) —
  you know the failure mode best.
- **Both fixtures.** Ship a *vulnerable* fixture (true-positive) and a *patched*
  fixture (true-negative). A probe without a passing patched-fixture test does
  not ship.

## Testing (spec §3.4)

`perimeter probe new <family>/<name>` creates a complete package with a typed
probe, separate manifest, strict empty-options schema and runnable Node fixture
tests. The diagnostic starter claims no vulnerability; replace its tests with
real vulnerable/patched controls when implementing your security behavior.
See [the scaffold walkthrough](first-probe.md) for build, test and loader commands.

Use the recorded-fixture harness — no live target needed:

```ts
import { runProbeAgainstFixtures } from "@perimeter/core";
const { reports } = await runProbeAgainstFixtures(myProbe, { target, fixtures });
```

See [`cross-tenant-read.test.ts`](../../packages/probes-standard/src/tenant-isolation/cross-tenant-read.test.ts)
for the canonical vulnerable + patched pair.

## Next

- [Write your first probe](./first-probe.md) — the end-to-end tutorial.
- [Finding schema](../finding-schema.md) — the evidence & remediation shape.
