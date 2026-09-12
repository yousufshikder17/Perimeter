# Reviewed role / function authorization

`auth/role-access` checks whether a valid lower-privilege identity can read a
function explicitly forbidden by application policy. It does not infer role
hierarchies from names or guess admin routes. Model two actual principals with
different roles in the **same tenant**, and review the GET routes as read-only.

```yaml
- id: profile
  method: GET
  path: /profile
  auth: required
- id: adminReport
  method: GET
  path: /admin/report
  auth: required
  roleAccess:
    readOnly: true
    deniedByPolicy: true
    allowedIdentity: tenantA.admin
    deniedIdentity: tenantA.user
    resultPath: [reportId]
    control:
      endpointId: profile
      resultPath: [id]
      expectedValue: member-id
```

`control.expectedValue` must identify the restricted principal using a non-secret
session field. This catches expired, wrong, or accidentally privileged test
credentials instead of crediting their rejection as role authorization. The
control endpoint must reject anonymous access and return that value as the
restricted identity. The privileged GET must return a nonempty protected string
or finite number selected by `resultPath`. Choose a distinguishing protected
value, not a public label, success boolean, or generic counter.

The final identical GET as the restricted identity produces HIGH/FIRM evidence
only if it exposes the same captured protected value, even in an error-status
body. Four audited exchanges connect the session controls and role comparison.
401/403 without the selected value is a scoped pass; redirects, other statuses,
different data, failed controls, cached data, missing/redacted/truncated evidence,
and insufficient budget are inconclusive. HTTP 200 alone is not a finding.

Select `auth/role-access` in `include`, select family `auth`, or use the default
standard library. Calls use the existing guarded HTTP client, credentials,
rate/request limits, 16 KiB response bound, cancellation, reports and read-only
checkpoint replay. No new dependency or privileged target operation is added.

This contract supports literal REST GET paths only: no object placeholders,
query strings, route guessing, GraphQL/gRPC combinations or write operations.
Use the existing object-ownership and protocol probes for their respective
contracts. This is not exhaustive authorization coverage or session-fixation
testing, and it relies on the correctness of your declared policy and identities.
