# Safety model

Safety is a **systemic** property, not a per-probe courtesy (spec §4.2, §10 risk
1). A misbehaving or malicious probe cannot escape these invariants because it
has no path to the network except the guarded client.

| Threat | Engine control |
|---|---|
| **Data modification** | Read-only default. Probe writes require manifest `safety.class` + `--allow-mutating` + authorized Target Model. Method and exact URL must bind to an engine-created scratch object. Mass-assignment uses idempotent scratch writes; writes run sequentially after reads and cannot use checkpoint replay. |
| **Data exfiltration** | Egress allow-listed to the modeled target host(s) only. No outbound channel elsewhere; evidence stays local. |
| **Denial of service** | Global + per-host token-bucket limiter, per-probe budgets, concurrency caps, bounded payloads. Rate-limit probes self-terminate on first observed throttle. Time-based injection is opt-in and bounded. |
| **Collateral on prod** | Mandatory `authorization` block; production requires extra confirmation and forces the most conservative rate profile. |
| **Runaway scans** | Global wall-clock + total-request ceiling per scan; `AbortSignal` halts everything cleanly. |

## The choke point

Every request passes through `SafetyGuard.check()` (`packages/core/src/safety/guard.ts`):
host allow-list → method policy → payload inspector → scratch-object rule. The
`GuardedHttpClient` calls it on **every** egress, after consuming the per-probe
budget and before waiting on the rate limiter.

## Enforcement layers

1. **Type system** — `ProbeContext` exposes no raw network, clock, or RNG.
2. **Linter** — `perimeter probe lint` statically rejects `fetch`, `undici`,
   `Math.random`, `Date.now`, and evidence-less findings (spec §3.4).
3. **Runtime guard** — the non-bypassable choke point above.
4. **CI safety-invariant suite** — `pnpm test:safety` proves the engine cannot
   exceed caps, egress off-target, issue destructive verbs, or run without
   authorization (spec §8.9). A regression here is release-blocking.

## Authorized testing only

Perimeter refuses to run without `authorization.iAmAuthorizedToTest: true`
(spec §5.5). Production targets additionally require
`PERIMETER_CONFIRM_PRODUCTION=yes` and are forced to a 1 rps profile. Using
Perimeter against systems you are not authorized to test is out of scope and may
be illegal — see [SECURITY.md](../SECURITY.md).
