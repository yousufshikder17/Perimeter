# Security Policy

Perimeter is an adversarial testing tool, so its own safety posture matters twice
over.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repo) or email **secops@perimeter.example**
(placeholder). Do not open public issues for undisclosed vulnerabilities.

We especially want to hear about:

- **Egress bypass** — any path by which a probe reaches the network *without*
  going through the `GuardedHttpClient` (spec §4.2, risk §10.1). This is
  treated as **release-blocking**.
- **Safety-guard bypass** — destructive verbs, off-target hosts, or rate-cap
  evasion.
- **Secret leakage** — credentials or tokens surfacing in audit logs, evidence
  bundles, or reports (redaction is applied on write; a leak is a defect).

## Scope of intended use

Perimeter must only ever be pointed at **non-production or explicitly-authorized
targets** (spec §2.3, §5.5). The engine refuses to run without an `authorization`
block. Using it against systems you are not authorized to test is out of scope
for this project and may be illegal.
