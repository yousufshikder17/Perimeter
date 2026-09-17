# Custom probe options

Configure reviewed custom probes by exact installed ID, not by family:

```yaml
probePaths: [./probes/diagnostics/my-check/dist/probe.js]
include: [diagnostics/my-check]
probeOptions:
  diagnostics/my-check:
    endpointId: health
```

Each manifest declares `configSchema`, either inline JSON Schema draft 2020-12
or a local JSON file. Generated probes import their JSON schema as pure data;
the generated build copies it into `dist/`. For legacy string references loaded
through `probePaths`, paths resolve against the nearest package.json ancestor of
the imported module (or its directory if none exists). Absolute local paths work.
Programmatic probes and declarative isolated-worker schema paths resolve against
the process working directory. No remote schema loading or Zod module imports.
Only bundled/local-fragment references can resolve; external references fail.

The host uses strict [Ajv validation](https://ajv.js.org/strict-mode), without
coercion, default insertion, unknown-field removal, async validators or custom
keywords. Declare `additionalProperties: false` on object schemas to reject
typos. Omitted options are `{}`; no schema means only empty options are accepted.
Unknown probe IDs and duplicate installed IDs fail closed. Applicable probes
are validated even without explicit options; explicitly configured options are
also validated when their probe is excluded. Unselected probes without supplied
options do not need their required fields filled in.

Validation precedes authentication hooks, fixture provisioning, worker startup
and probe traffic. Errors identify the probe without echoing schema/option values.
The copied options are deeply frozen and exposed as `ctx.options` in `plan` and
`run`. Legacy/custom contexts may omit that field. The fixture harness accepts
`runProbeAgainstFixtures(probe, { target, fixtures, probeOptions: {...} })` and
uses the same validator. Isolated workers receive only their own options in the
additive protocol v1 `start.options` field; existing workers may ignore it.

Options are JSON objects with finite numbers, at most 64 KiB serialized size,
depth 16 and 10,000 visited values. Schema documents have the same limits.
Prototype-manipulation keys, cyclic/non-JSON values and sparse arrays are refused.
Schemas and in-process probes are reviewed operator code/data, not a sandbox
against malicious schema patterns or JavaScript. Keep schemas simple and bounded.

Do not put secrets in options. Use modeled identity handles instead. Options do
not widen request budgets, allowed hosts, identities, write approval or any other
engine safety policy. A worker cannot use options to grant itself permissions.
Option changes invalidate checkpoint compatibility. CLI-loaded file schema
contents are included in the resolved manifest used for checkpoint compatibility;
programmatic callers should use inline schemas and bump probe versions when their
code/schema contract changes.
