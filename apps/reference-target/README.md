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

## Optional real PostgreSQL

The default remains in-memory. For real RLS, create a **new disposable database**
on PostgreSQL 17+, apply `db/schema.sql` as its administrator, and assign a
password with `psql`'s `\password perimeter_reference`. Set
`PERIMETER_REFERENCE_DATABASE_URL` to that database's connection URL using the
`perimeter_reference` role, then run the usual start command. Never use the
administrator/owner connection for the app. PostgreSQL can be installed locally,
run through Docker/Podman, or hosted in your own isolated test environment.

SQL policy configuration, not `FIX_CROSS_TENANT`, controls isolation in this
backend. The supplied policy is patched; the commented `ALTER POLICY` command
provides an explicitly broken read policy. `FIX_IDOR` still controls application
ownership checks. Each operation sets transaction-local tenant context on the
same pooled connection; missing context sees no rows. The server binds loopback.

After `pnpm build`, run the real integration test with
`PERIMETER_TEST_POSTGRES=1 pnpm test tests/e2e/postgres-reference.test.ts`
(PowerShell: set `$env:PERIMETER_TEST_POSTGRES='1'` first).
It starts a unique `postgres:17-alpine` Docker container on an ephemeral loopback
port and removes it afterwards, without persistent volumes. Without the opt-in,
only that live test is skipped; the memory regression runs normally.

Reference: [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
Missing policies with RLS enabled deny access; they do not inherently leak rows.
