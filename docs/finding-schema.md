# Finding schema

Findings are the one output family (spec §6). Schema-first (Zod is the source of
truth), versioned, evidence-backed, actionable, and stably fingerprinted for CI
diffing. Emitted as JSON, rendered to Markdown, and mapped to SARIF/JUnit.

## Principles (§6.1)

- **Versioned.** `schemaVersion` is semver; probes declare what they emit.
- **Evidence non-optional.** Every finding carries the sanitized request/response
  that proves it — the registry enforces this at intake.
- **Actionable.** `severity` + `remediation` are required, not nice-to-haves.
- **Stable identity.** A deterministic `fingerprint = hash(probeId + endpoint +
  class + locator)` lets CI baseline, suppress accepted findings, and detect
  regressions.

## Shape (§6.2–6.4)

```ts
interface Finding {
  id: string;                 // ULID
  fingerprint: string;        // stable, for diffing
  schemaVersion: string;
  probeId: string; family: ProbeFamily; title: string;
  severity: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO";
  confidence: "CONFIRMED"|"FIRM"|"TENTATIVE";
  cwe?: string[]; owaspApi?: string[];
  target: { endpointId; method; path; tenantScoped?; objectRef? };
  affectedIdentities: IdentityRef[];
  evidence: Evidence;         // mandatory (see below)
  remediation: Remediation;   // mandatory: guidance + references [+ codeHints, effort]
  firstSeen; lastSeen; status: "open"|"accepted"|"fixed"|"suppressed";
}

interface Evidence {
  summary: string;
  exchanges: HttpExchange[];              // ≥1, sanitized request/response pairs
  differential?: { baseline; probe; diff };
  reproduction: { seed; steps; curl? };  // redacted creds
  auditRefs: string[];                    // content-addressed pointers into the audit log
}
```

A `Pass` is an explicit non-finding, so a report can show "login IS rate-limited"
rather than silent absence.

## Formats (§6.5)

| Format | Purpose |
|---|---|
| **JSON** | Full registry — the machine contract; drives the SARIF exporter. |
| **Markdown** | The default human report: summary, rollup, per-finding evidence + remediation. |
| **HTML** | Self-contained, script-free report for local review or artifact hosting. |
| **SARIF** | GitHub code-scanning / inline PR annotations. |
| **JUnit** | Generic CI dashboards. |

All output formats are open — no lock-in (spec §7.2). Compliance-mapped packs
(SOC 2 / ASVS / API Top 10) are premium.

## Baselines

A baseline is a versioned JSON document containing the reviewed finding
fingerprints for one target. Generate it from a full JSON scan artifact with an
explicit acknowledgement:

```bash
perimeter baseline create findings.json --out perimeter-baseline.json --accept-current
```

Baseline files are validated strictly and never overwritten by this command.
Accepted findings remain visible in reports but do not fail the severity gate.
