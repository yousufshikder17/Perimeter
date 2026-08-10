# Write your first probe

A 10-minute tour from scaffold to a passing fixture test. We'll write a small
`auth/missing-auth` probe (a simplified sibling of the standard auth family).

## 1. Scaffold

```bash
pnpm cli probe new auth/missing-auth --dir probes
```

This creates `probes/auth/missing-auth.ts` from the template with a typed
manifest and empty `plan()`/`run()`.

## 2. Declare requirements

The probe only applies where there's an auth-required endpoint. In the manifest:

```ts
requires: { endpoints: ["authRequired"] },
safety: { class: "read-only", maxRequests: 10, destructive: false },
```

## 3. Plan (no network here)

```ts
async plan(ctx) {
  const targets = ctx.target.endpoints.filter((e) => e.auth === "required" && e.method === "GET");
  if (targets.length === 0) return skip("no auth-required GET endpoint");
  return {
    probeId: this.manifest.id,
    steps: targets.map((e) => ({ id: `authz:${e.id}`, description: `anon ${e.path}`, endpointId: e.id, estimatedRequests: 1 })),
  };
}
```

## 4. Run (all egress via ctx.http; evidence mandatory)

```ts
async run(plan, ctx) {
  for (const step of plan.steps) {
    if (ctx.signal.aborted || !ctx.budget.available()) return;
    const e = ctx.target.endpoints.find((x) => x.id === step.endpointId)!;
    const anon = await ctx.http.get(e.path); // no `as` → no credential
    if (anon.status >= 200 && anon.status < 300) {
      ctx.report(buildFinding({ /* severity CRITICAL, evidence: [anon.exchange], remediation … */ }));
    }
  }
}
```

The engine records `anon.exchange` in the audit log; attach it to `evidence.exchanges`.

## 5. Prove both sides

```ts
// vulnerable fixture → 200 for anon → expect one finding
// patched fixture    → 401 for anon → expect zero findings
const { reports } = await runProbeAgainstFixtures(missingAuth, { target, fixtures });
```

## 6. Lint & test

```bash
pnpm cli probe lint probes/auth/missing-auth.ts   # §3.2 safety contract
pnpm vitest run probes/auth                        # fixtures
```

Green on both? Open a PR — see [CONTRIBUTING](../../CONTRIBUTING.md).
