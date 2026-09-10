# Perimeter Documentation

> Application-aware adversarial resilience testing for multi-tenant SaaS.

Start here, then dive into whichever area you need.

| Doc | What it covers |
|---|---|
| [Architecture](./architecture.md) | The layered runtime, the data flow, and why every vulnerability class shares one pipeline (spec §2). |
| [Safety model](./safety.md) | The engine-level "never destructive" invariants and how they're enforced (spec §4.2, §8.9). |
| [Target Model](./target-model.md) | How you describe a target's auth, tenancy, and endpoints (spec §5). |
| [Finding schema](./finding-schema.md) | The versioned finding + evidence + remediation contract (spec §6). |
| [CSV export checks](./csv.md) | Harmless scratch formula canaries and bounded CSV evidence. |
| [Mass-assignment checks](./mass-assignment.md) | Opt-in scratch PATCH controls, persisted-field verification and cleanup. |
| **[Probe Authoring Guide](./authoring/README.md)** | **The moat.** The safety contract, the "good probe" rubric, and the fixture requirement (spec §3). |
| [Write your first probe](./authoring/first-probe.md) | End-to-end tutorial from `probe new` to a passing fixture test. |

## Quickstart

```bash
pnpm install && pnpm build

# 1) Run the deliberately-vulnerable reference target
pnpm --filter @perimeter/reference-target start &

# 2) Validate the example Target Model, then scan
pnpm cli model validate examples/target.yaml
pnpm cli scan --config examples/scan.yaml

# → report.md + findings.json (+ SARIF/JUnit), gated by --fail-on
```

Docs are authored as Markdown and render with Docusaurus/mkdocs-material (spec
§9) — the probe-authoring guide is a first-class doc because the ecosystem lives
or dies on it.
