# @perimeter/reference-target

A **deliberately-vulnerable** multi-tenant SaaS (Hono + Postgres RLS model) used
for end-to-end probe tests and the safety-invariant suite (spec §9). It is the
analog of "software-in-the-loop": probes run against it with zero external
dependencies.

> ⚠ **Never deploy this.** By default it intentionally leaks across tenants.

## Run

```bash
pnpm --filter @perimeter/reference-target build
pnpm --filter @perimeter/reference-target start   # :8080, fully vulnerable
```

## Vulnerability toggles (env)

| Env | Effect |
|---|---|
| _(default)_ | Vulnerable: cross-tenant read + IDOR + no rate limit. |
| `PERIMETER_PATCHED=1` | Patch everything (true-negative fixture). |
| `FIX_CROSS_TENANT=1` | Enforce the tenant boundary on reads. |
| `FIX_IDOR=1` | Enforce object ownership. |
| `FIX_RATE_LIMIT=1` | Throttle `/auth/login`. |
| `BREAK_AUTH=1` | Serve protected routes without auth. |

The same binary serves as both the vulnerable and patched fixture, so a probe can
prove its true-positive and true-negative against one app.

See [`db/schema.sql`](./db/schema.sql) for the real Postgres RLS policy the
in-memory store models.
