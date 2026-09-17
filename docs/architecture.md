# Architecture

Perimeter is one TypeScript runtime with three layers (spec §2). The crucial
choice: **every vulnerability class flows through the identical pipeline.** A
tenant-isolation probe and a rate-limit probe are peers — same lifecycle, same
safety envelope, same finding schema, same audit trail. New classes are plugins,
not forks.

## Layers

```
OUTPUTS        Findings (MD/JSON/HTML), CI gate (SARIF/JUnit), [future: compliance packs]
CORE RUNTIME   Orchestrator · Execution engine (sched/QoS) · Finding registry · Safety guard
               Target Model · Evidence/audit log (append-only, replayable)
PROBE LAYER    tenant-isolation · idor · injection · auth · rate-limit · graphql
               csv · mass-assignment · grpc · ssrf (+ community)
TARGET         reviewed REST/GraphQL/unary-gRPC APIs
```

## Data flow (spec §2.2)

1. **Target Model** loaded (declarative + optional discovery): auth recipe,
   tenant structure, annotated endpoint inventory.
2. **Orchestrator** selects applicable probes by matching each probe's `requires`
   against the model. Unsatisfiable probes are **skipped with a reason**, never
   silently.
3. **Execution engine** schedules probe steps through the **safety guard** and
   the **global rate limiter**. Every request is stamped, audited, and tagged
   with probe/identity/tenant.
4. Probes emit **findings** or explicit **passes** into the **finding registry**.
5. **Reporters** render the registry (Markdown/JSON/HTML and SARIF/JUnit;
   compliance packs are future work). CI maps findings to an exit code + inline
   annotations.

## Package map

| Package | Role |
|---|---|
| `@perimeter/sdk` | The public probe contract, finding schema, Target Model. The only surface premium depends on. |
| `@perimeter/core` | Orchestrator, engine, safety guard, rate limiter, audit log, identity/fixtures, discovery, reporters, test harness. |
| `@perimeter/probes-standard` | Ten standard families, including bounded protocol, auth/session and scratch-write checks, authored as plugins. |
| `@perimeter/probe-linter` | Static enforcement of the §3.2 safety contract. |
| `@perimeter/cli` | `scan / model / probe / report / baseline / compare / callbacks`. |
| `@perimeter/reference-target` | Deliberately-vulnerable Hono test app; default memory store and optional real PostgreSQL/RLS backend. |

## Process model (local/CI)

A single Node process hosts the orchestrator, engine (async, concurrency-bounded),
trusted in-process probes, the safety guard, and the audit-log writer. Declarative
`isolatedProbes` launch external workers over portable NDJSON stdin/stdout, using
a restricted container runner or an explicitly operator-managed command runner.
The parent owns target requests, credentials, budgets, and recorded evidence.
See [isolated probes](isolated-probes.md) for Docker, compatible runtimes, manual
operation, and the distinction between process isolation and a security sandbox.

## Deployment profiles (spec §2.3)

**Local** (laptop/`npx`), **CI** (ephemeral runner, deterministic, machine
output, gating). **Managed cloud** is a future premium service, not a currently
available configuration mode. Scans require explicit authorization, with
additional confirmation for production targets.
