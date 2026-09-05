# Target Model

The Target Model is the differentiator (spec §5): it lets probes reason about
_tenants, identities, and object ownership_ rather than URLs. It's declarative
(YAML/JSON/TS), validated by Zod, with optional discovery to bootstrap it.

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

## Custom credentials

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
```

Hooks are trusted operator code, like executable Target Models. Importing one
executes its module after the scan's authorization gate; this is not a sandbox
for untrusted plugins. Keep secrets in environment variables or a local secret
store. `model validate` validates the configuration without executing the hook.
