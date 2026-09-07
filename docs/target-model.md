# Target Model

The Target Model is the differentiator (spec §5): it lets probes reason about
_tenants, identities, and object ownership_ rather than URLs. It's declarative
(YAML/JSON/TOML/TS), validated by Zod, with optional discovery to bootstrap it.

Both target files and CLI scan configs accept `.toml`. TOML uses the same
schema, defaults, and authorization requirements as YAML/JSON. For example:

```toml
target = "examples/target.toml"
failOn = "HIGH"
[output]
json = "findings.json"
markdown = "report.md"
```

See [`examples/target.yaml`](../examples/target.yaml) for a complete example.

## Sections

- **`auth`** (§5.1) — how identities are minted: `api_key | bearer |
oauth2_password | session_cookie | custom`. Secrets are **never inline** — only
  `credentials: { env: ... }` refs. A `custom` scheme points at a TS hook.
- **`identities`** — one entry per tenant/role the engine must mint.
- **`tenancy`** (§5.2) — `shared_db_rls | schema_per_tenant | db_per_tenant |
header_scoped`, plus the discriminator (`jwt_claim | header | subdomain |
path_param`) and the tenant list (≥2 for isolation probes).
- **`endpoints`** (§5.3) — the operations probes target, with the **semantic
  annotations** that make application-aware testing possible:
  `tenantScoped`, `objectRef`, `creates`, `rateSensitive`, `injectable`, `auth`.
  These are the vocabulary probes match against via `requires`.
- **`authorization`** (§5.5) — **mandatory**. The engine refuses to run without
  `iAmAuthorizedToTest: true`. `environment: production` triggers extra
  confirmation and the strictest rate caps.

## Discovery (optional bootstrap, §5.4)

```bash
perimeter model discover openapi.yaml --out draft.yaml
perimeter model discover collection.json --from postman --out draft.yaml
perimeter model discover capture.har --from har --out draft.yaml
```

Infers a **draft** inventory from an OpenAPI spec, Postman Collection v2.x, or
HAR 1.2 capture. Ownership
semantics are never guessed silently — inferred `objectRef`/`tenantScoped` come
out as review notes you confirm before the model is trusted.

## Validate

```bash
perimeter model validate examples/target.yaml
```

## Scratch fixture payloads

Factory endpoints may supply `fixture.body` with the required JSON fields for
creating a disposable object. Without it, the existing empty-object request is
used. Authentication still comes from the identity being provisioned.

```yaml
endpoints:
  - id: createInvoice
    method: POST
    path: /api/invoices
    creates: invoice
    fixture:
      body:
        amountCents: 100
        memo: perimeter scratch invoice
        labels: [security-test]
      responseIdPath: [data, invoice, uuid]
```

The body must be a JSON object; nested objects, arrays, numbers, booleans, and
null are supported. Fixture configuration is accepted only on POST factories
with `creates`. Requests still pass through the same payload policy, host guard,
rate limits, request budget, and audit writer. Use non-secret disposable data:
the body is captured in audit records. There is no template expansion or
per-identity substitution; tenant ownership should come from authentication.

For a response such as `{"data":{"invoice":{"uuid":"inv-123"}}}`,
`fixture.responseIdPath: [data, invoice, uuid]` identifies the created object's
ID. Segments are literal JSON keys, not dotted paths or expressions; use a
string index such as `"0"` to traverse an array. The result must be a non-empty
string or finite number (including zero). This ID is shared with probes and
used to resolve the modeled DELETE endpoint for cleanup.

An explicit mapping takes precedence over `id`, `<kind>Id`, `data.id`, and
`Location`. Invalid JSON, a missing path, or an invalid ID fails that fixture's
provisioning without guessing another object; the engine records the failure
and dependent probes cannot use that fixture. Without `responseIdPath`, the
existing ID heuristics remain unchanged. If the server created an object but
returned an unusable ID, the scanner cannot track or automatically remove it.

## Custom credentials

For environment-backed credentials, a missing `credentials.env` reference,
an unset environment variable, or a blank value fails the scan when that
identity is used. The error identifies the configuration to fix without
printing a credential. The engine never substitutes a placeholder token.

CLI scans load `auth.customHook` when `auth.scheme` is `custom`. The hook is a
local module with a default-exported function receiving `{ ref, tenant, role }`
and returning a promise of credential headers. Relative paths resolve against
the Target Model's directory, regardless of the shell's working directory.
Use `.mjs` for portable Node support; TypeScript requires runtime loader support.
Missing files and non-function exports fail the scan before fixture setup.

```yaml
auth:
  scheme: custom
  customHook: ./credentials.mjs
  refresh: { ttlSeconds: 300 }
```

```js
// credentials.mjs — return pre-issued credentials from your local secret store.
const keys = { "tenantA.user": "TENANT_A_TOKEN", "tenantB.user": "TENANT_B_TOKEN" };
export default async function credentials({ ref }) {
  const token = process.env[keys[ref]];
  if (!token) throw new Error("Missing configured credential");
  return { authorization: `Bearer ${token}` };
}
```

Credential headers are cached per identity for `refresh.ttlSeconds` (default:
3600 seconds). Concurrent requests share one hook call, and expiry invokes the
hook again, including for retained identity handles. The core does not call
`refresh.endpoint` for custom hooks. Hook failures are not cached and fail the
scan; their messages are withheld from reports and logs to avoid leaking secrets.
Supported header names are `authorization`, `cookie`, `x-api-key`, and
`x-auth-token` (case-insensitive), all redacted in audit records. Empty values,
duplicate names, invalid HTTP header values, and other header names are rejected.

Hooks also receive the scan's `signal`. Forward it to asynchronous credential
work so cancellation can stop that work. The core stops waiting when a scan is
cancelled; it cannot terminate arbitrary code or resources created by a hook.

Hooks are trusted operator code, like executable Target Models. Importing one
executes its module after the scan's authorization gate; this is not a sandbox
for untrusted plugins. Keep secrets in environment variables or a local secret
store. `model validate` validates the configuration without executing the hook.
Hook-owned I/O is outside the guarded probe HTTP path; this feature does not
implement an OAuth/password exchange, a login request contract, or token refresh
endpoints. Those still require a real target's authentication requirements.
