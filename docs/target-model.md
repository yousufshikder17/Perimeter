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

### Authenticated crawl

```bash
perimeter model crawl target.yaml --as tenantA.user --start /api/ \
  --max-pages 50 --max-depth 3 --max-seconds 120 \
  --audit-log crawl-audit.ndjson --out draft.yaml
```

Uses the configured identity and the normal scan authorization gate, rate limits,
credential exchange/refresh, audit log, and cancellation. Production still needs
`PERIMETER_CONFIRM_PRODUCTION=yes`. An empty `endpoints` list is allowed for
bootstrapping; crawling never provisions scratch fixtures or submits forms.
Built-in authentication can POST to the explicitly configured login/token URLs;
all discovery requests are GETs. Only crawl targets you are authorized to test
and whose GET handlers are safe for that identity.

Traversal is breadth-first on the exact target origin (scheme, host, and port).
It follows HTML anchor/area links (including the first HTML base URL), JSON
`href`/`url` string fields, and explicit redirect destinations. Fragments are
removed; duplicate URLs are visited once. Userinfo and external URLs are rejected.
Query-bearing links are omitted with a review note, not silently rewritten.
There is no JavaScript execution, browser OAuth, asset fetching, form submission,
parameter guessing, or automatic cookie jar beyond the configured session cookie.

Defaults are 50 GET requests, depth 3 (start is depth 0), and 120 seconds.
Limits accept 1–1000 pages, depth 0–10, and 1–3600 seconds. Redirects count against
both page and depth limits. Total guarded requests, including authentication,
are capped at twice `max-pages`. Each response, including authentication, is
limited to 1 MiB; oversized responses, authentication/access failures (401/403),
network errors, and timeouts fail the command without emitting a successful
partial draft. Page/depth limits and other non-success responses produce explicit
review notes. Unsupported response types can be inventoried but are not parsed.

Only successful GET paths enter the draft. `auth: optional` is a placeholder for
review, not a verified property: authenticated access cannot establish whether
anonymous access is denied. Concrete resource IDs are not generalized into route
parameters. Confirm authentication, tenant scope, ownership, and all paths before
using this inventory in a scan. This is linked endpoint discovery, not exhaustive
API coverage.

Without `--out`, stdout is YAML only; review notes go to stderr. `--out` creates
a new file and refuses to overwrite an existing model. The audit log is appended
locally with credential headers redacted and response bodies withheld. Treat
paths and other response metadata as potentially sensitive local artifacts.

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
Hook-owned I/O is outside the guarded probe HTTP path.

## Built-in authentication exchange

The authentication probe also supports engine-generated JWT test credentials;
see the JWT checks below for the separate expired-token fixture contract.

`oauth2_password` now performs the standard form-encoded password grant and
refresh-token grant rather than treating the environment value as a bearer token.
Each identity's `credentials.env` names a JSON string containing `username` and
`password`, with optional `client_id`, `client_secret`, and `scope`. This is the
legacy password grant for targets that explicitly support it; it is not browser
OAuth, authorization-code/PKCE, device login, or MFA.

```yaml
auth:
  scheme: oauth2_password
  tokenEndpoint: /oauth/token
  refresh: { endpoint: /oauth/token, ttlSeconds: 300 }
```

Responses require `access_token` and Bearer `token_type`; `expires_in` and
`refresh_token` are optional. Credentials expire at the smaller of the returned
lifetime and configured TTL (default 3600 seconds). Refresh tokens are isolated
per identity and rotated when the response supplies a new one. Without a refresh
token, expiry repeats the password exchange. A failed refresh fails that scan;
it is never silently accepted or retried with a different identity.

For application-specific session login, configure the body encoding and cookie:

```yaml
auth:
  scheme: session_cookie
  tokenEndpoint: /auth/login
  login: { format: json, cookieName: session }
```

The credential environment variable contains a JSON object of string fields sent
verbatim as JSON (or `format: form`). A single matching Set-Cookie is required.
Expiry uses Max-Age/Expires and the configured TTL; renewal repeats login. With
no `tokenEndpoint`/`login`, session_cookie still uses its pre-issued env value.

Authentication endpoints must be on the target origin. Requests use the shared
budgets, rate limits, cancellation, and guarded HTTP client. Redirects and non-2xx
responses fail authentication. Request/response bodies are fully redacted from
authentication audit entries; returned tokens/cookies are redacted from ordinary
request headers. Non-sensitive audit metadata remains available. The engine
supports the [OAuth password and refresh contracts](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.3).

## JWT authentication checks

`auth/token-manipulation` checks missing authentication and four JWT variants:
`none-alg`, `signature-stripped`, `tenant-swapped`, and `expired`. Run the normal
scan with `include: [auth]` to select the authentication family.

JWT checks require exactly one Bearer authorization header containing a signed,
compact JWT (maximum 16 KiB), whether supplied statically, through OAuth, or by a
custom hook. API keys, opaque tokens, cookies, unsigned tokens, and identities
with additional credential headers are not used for these checks. The engine
does not silently fall back to the original token if a variant is unavailable.

For non-parameterized protected GET endpoints, the probe uses the first modeled
identity. Parameterized endpoints need an existing engine-provisioned scratch
object: its owner is used and its ID is URL-encoded into the declared object
parameter. Unresolved parameters are omitted with a warning. This probe does not
create fixtures itself or guess real resource IDs.

Anonymous access must return 401/403 and the live credential must return 2xx
before any variant is tried. Anonymous success remains the existing missing-auth
finding; it does not also produce forged-token findings. Each variant is sent
through the guarded client, with normal rate limits, audit redaction, cancellation,
and the existing 30-request probe ceiling. A full endpoint check costs at most six
GETs. Authentication exchanges additionally consume the shared scan budget.
Inapplicable checks and inconclusive controls/rejections are logged as warnings,
not reported as security passes.

`tenant-swapped` is available only when the configured JWT claim equals the
identity's modeled tenant and another tenant is modeled. It changes that claim
while retaining the original signature. Acceptance indicates possible integrity
validation failure, not proof that another tenant's data was disclosed.

To check actual expiry separately from signature tampering, supply a raw,
pre-issued expired JWT through an environment variable (no `Bearer` prefix):

```yaml
identities:
  - ref: tenantA.user
    tenant: tenant-a
    role: member
    credentials: { env: TENANT_A_LIVE_TOKEN }
    expiredCredentials: { env: TENANT_A_EXPIRED_TOKEN }
```

The expired sample must use the live token's algorithm, have the same claims
except `exp`, `iat`, `nbf`, and `jti`, and be expired for at least 60 seconds.
Missing or invalid configured samples fail the scan without logging their value.
Without a configured sample, only the expiry check is omitted. The operator must
ensure its signature is genuinely valid for the target and that expiry exceeds
the target's allowed clock skew; the engine decodes but cannot verify the target's
signature without its verification keys. Live credential caches are never changed
by test variants, and an expired sample is never refreshed into a live token.

Variant success produces a HIGH/FIRM finding with anonymous, live, and modified
request evidence and a distinct fingerprint per variant. A 2xx response alone is
not conclusive proof of protected-data access: review response semantics before
confirming a bypass, particularly for login pages and APIs using 2xx error bodies.
