# Perimeter

**Application-aware adversarial resilience testing for multi-tenant SaaS.**

Perimeter automatically generates and executes adversarial test suites against
multi-tenant SaaS applications, targeting the failure modes generic web scanners
miss: **tenant isolation boundaries, IDOR, injection, authentication boundaries,
and rate limiting.** It understands application-level concepts — *this token
belongs to tenant A, that record belongs to tenant B, this endpoint should never
cross that line* — and expresses attacks as **probes** against a modeled target,
not blind HTTP fuzzing.

From one declarative Target Model and a library of probes, you get **findings**:
structured, evidence-backed vulnerability reports (Markdown + JSON, with SARIF and
JUnit), gated into CI/CD — safe, rate-limited, and fully audited by construction.

> Status: **Draft v0.1** scaffold under active development. See
> [`docs/`](./docs/README.md) for the public architecture and usage documentation.

---

## Why not Burp / ZAP?

They see URLs. Perimeter sees *a tenant-scoped object read with a referenceable
id*. The differentiator is **semantic understanding of multi-tenant SaaS**, not
HTTP interception. We go deep on application logic instead of wide on HTTP
surface — and complement, rather than replace, a DAST.

## Design pillars

- **Application-aware, not proxy-aware** — the engine reasons about tenants,
  identities, and object ownership.
- **The probe library is the moat** — a pluggable probe/adapter pattern; every
  vulnerability class shares one lifecycle contract. Contributor experience is a
  first-class concern.
- **Safe by construction** — read-only by default; explicitly enabled write
  probes target engine-created scratch records only. Rate-limited and audited. Destructive
  capability is not a flag you can flip in core.
- **Extensible architecture** — the engine, SDK, CLI, and probe library share
  explicit contracts so new capabilities can be added without bypassing safety.
- **CI-native** — the GitHub Action is an MVP feature, not an afterthought.

## Quickstart

```bash
pnpm install
pnpm build

# Run the deliberately-vulnerable reference target (spec §9)
pnpm --filter @perimeter/reference-target start &

# Validate the Target Model and scan
pnpm cli model validate examples/target.yaml
pnpm cli scan --config examples/scan.yaml
#   → report.md + findings.json (+ SARIF/JUnit); exits non-zero on the gate
```

## Repository layout

```
packages/
  sdk/                @perimeter/sdk              — public probe contract, finding schema, Target Model
  core/               @perimeter/core             — orchestrator, engine, safety guard, rate limiter,
                                                    audit log, identity/fixtures, discovery, reporters, harness
  probe-linter/       @perimeter/probe-linter     — static §3.2 safety-contract enforcement
  probes-standard/    @perimeter/probes-standard  — standard probe families (plugins)
  cli/                @perimeter/cli              — scan / model / probe / report
apps/
  reference-target/   @perimeter/reference-target — vulnerable Hono + Postgres-RLS SaaS for tests
action/               GitHub Action (composite)   — CI scan + SARIF upload + gating
docs/                 architecture, safety, Target Model, finding schema, PROBE AUTHORING GUIDE
tests/safety/         the gated safety-invariant suite (spec §8.9)
examples/             target.yaml, scan.yaml, baseline.json
```

## Standard probe families

| Family | Core question |
|---|---|
| **tenant-isolation** | Can identity in tenant A observe or affect tenant B's data? |
| **idor** | Are object references authorization-checked, or just unguessable? |
| **injection** | Does untrusted input reach an interpreter? (non-destructive SQLi-first) |
| **auth** | Are authentication/authorization boundaries actually enforced? |
| **rate-limit** | Are abuse-sensitive endpoints actually throttled? |
| **graphql** | Do reviewed queries enforce protected-data authorization? |
| **csv** | Does a harmless scratch formula remain unneutralized in an export? |
| **mass-assignment** | Can a reviewed protected field be persisted through a scratch-object update? |
| **grpc** | Do reviewed unary RPCs enforce protected-data authorization? |
| **ssrf** | Does a scratch webhook contact an explicitly owned, policy-forbidden destination? |

See [CSV export checks](./docs/csv.md) and [mass-assignment checks](./docs/mass-assignment.md)
for required annotations, evidence boundaries and opt-in behavior.
See also [unary gRPC](./docs/grpc.md) and [owned SSRF/webhook checks](./docs/ssrf.md).

## Safety, in one line

A probe has **no path to the network except the guarded client** — rate-limited,
host-allow-listed, verb-policed, audited. These are engine-level invariants
proven by [`tests/safety/`](./tests/safety), not probe etiquette. See
[docs/safety.md](./docs/safety.md).

## CI/CD

```yaml
- uses: perimeter/perimeter/action@v0
  with: { config: perimeter.scan.yaml, fail-on: HIGH, seed: ${{ github.sha }} }
```

Applies a severity gate, uploads SARIF for inline PR annotations, and supports
baseline diffing so accepted findings don't break the build. See
[`action/README.md`](./action/README.md).

Create a baseline only after reviewing the full JSON scan artifact:

```bash
perimeter baseline create findings.json --out perimeter-baseline.json --accept-current
```

Set `baseline: perimeter-baseline.json` in the scan config. Invalid or missing
baseline files fail the scan instead of silently disabling suppression.

Compare two scan artifacts locally and optionally gate only on regressions:

```bash
perimeter compare previous.json current.json --format html --out comparison.html --fail-on HIGH
```

## Internal development

Probe implementation guidance is maintained in the
[Probe Authoring Guide](./docs/authoring/README.md). This repository is publicly
viewable for evaluation and portfolio purposes. No license is granted for
redistribution or derivative works.
