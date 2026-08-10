# Architecture

Perimeter is one TypeScript runtime with three layers (spec §2). The crucial
choice: **every vulnerability class flows through the identical pipeline.** A
tenant-isolation probe and a rate-limit probe are peers — same lifecycle, same
safety envelope, same finding schema, same audit trail. New classes are plugins,
not forks.

## Layers

```
OUTPUTS        Findings (MD/JSON), CI gate (SARIF/JUnit), [premium: compliance packs]
CORE RUNTIME   Orchestrator · Execution engine (sched/QoS) · Finding registry · Safety guard
               Target Model · Evidence/audit log (append-only, replayable)
PROBE LAYER    tenant-isolation · idor · injection · auth · rate-limit  (+ community)
TARGET         multi-tenant SaaS HTTP API (+ optional GraphQL/gRPC/DB-RLS adapters)
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
5. **Reporters** render the registry (Markdown/JSON in core; SARIF/JUnit; premium
   compliance packs). CI maps findings to an exit code + inline annotations.

## Package map

| Package | Role |
|---|---|
| `@perimeter/sdk` | The public probe contract, finding schema, Target Model. The only surface premium depends on. |
| `@perimeter/core` | Orchestrator, engine, safety guard, rate limiter, audit log, identity/fixtures, discovery, reporters, test harness. |
| `@perimeter/probes-standard` | The five standard families, authored as plugins. |
| `@perimeter/probe-linter` | Static enforcement of the §3.2 safety contract. |
| `@perimeter/cli` | `scan / model / probe / report`. |
| `@perimeter/reference-target` | Deliberately-vulnerable Hono+RLS SaaS for tests. |

## Process model (local/CI)

A single Node process hosts the orchestrator, engine (async, concurrency-bounded),
in-process probes, the safety guard, and the audit-log writer. A probe may declare
`isolation: "subprocess"` for a heavy/untrusted dependency; it speaks the same
probe protocol over a local IPC channel — the core doesn't care (spec §2.4).

## Deployment profiles (spec §2.3)

**Local** (laptop/`npx`), **CI** (ephemeral runner, deterministic, machine
output, gating), and **Managed cloud** (future, premium). One codebase, selected
by config. Across all profiles: Perimeter only ever points at non-production or
explicitly-authorized targets.
