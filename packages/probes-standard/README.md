# @perimeter/probes-standard

The five standard probe families (spec §3.3, §8), authored as plugins on
`@perimeter/sdk` — nothing in the engine special-cases a family name. The
`perimeter.probes` export is the package discovery convention (spec §3.1).

| Family | Probe (MVP) | Finding of |
|---|---|---|
| `tenant-isolation` | `cross-tenant-read` | Tenant A received tenant B's object. |
| `idor` | `sequential-id-swap` | A not-owned reference returned data. |
| `injection` | `sqli-differential` | Query-structure influence / DB error signature (non-destructive). |
| `auth` | `token-manipulation` | Protected resource served under absent/forged credential. |
| `rate-limit` | `burst-throttle` | Endpoint accepted N≫expected requests with no throttle (bounded). |

Each ships (or will ship) **both** fixtures — vulnerable (true-positive) and
patched (true-negative). See
[`tenant-isolation/cross-tenant-read.test.ts`](./src/tenant-isolation/cross-tenant-read.test.ts).
