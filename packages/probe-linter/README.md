# @perimeter/probe-linter

Static enforcement of the probe safety contract (spec §3.2, §3.4). Run via
`perimeter probe lint <path>` or embed programmatically:

```ts
import { lintFile, lintManifest } from "@perimeter/probe-linter";
const findings = await lintFile("probes/idor/my-check.ts");
```

## Rules

| Rule | Enforces |
|---|---|
| `no-raw-egress` | No `fetch`, `node:http/https`, `undici`, `axios`, `XMLHttpRequest` — egress only via `ctx.http`. |
| `deterministic-only` | No `Math.random()` / wall-clock reads — use `ctx.rng` / `ctx.clock`. |
| `evidence-on-finding` | A `report()` of a Finding must include an `evidence` bundle. |
| `manifest-complete` / `no-destructive` | Manifest validates; `safety.destructive` must be false; `mutating` flagged. |

A rule violation is **release-blocking** (spec §10 risk 1): the CI `probe-lint`
job fails the build.
