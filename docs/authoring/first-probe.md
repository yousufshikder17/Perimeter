# Write your first probe

The scaffold is a complete, runnable **transport diagnostic**, not a ready-made
vulnerability detector. Its tests exercise the real recorded-fixture harness;
they do not pretend to establish vulnerable/patched security coverage.

## Generate and test

From the repository root, after `pnpm install` and `pnpm build`:

```bash
node packages/cli/dist/bin.js probe new diagnostics/my-check --dir probes
pnpm --dir probes/diagnostics/my-check test
node packages/cli/dist/bin.js probe lint probes/diagnostics/my-check
```

Each invocation creates a new `probes/<family>/<name>/` package containing:

- `probe.ts`: typed read-only lifecycle and `perimeter.probes` loader export.
- `manifest.ts`: pure probe identity, requirements, budget and schema reference.
- `config.schema.json`: strict JSON Schema for the starter's empty options.
- `probe.test.ts`: three runnable recorded-fixture checks using Node's test runner.
- `package.json`: private ESM package with build/test scripts.

The test script typechecks/compiles the sources into `dist/`, then runs the
generated tests. Use an existing project with `@perimeter/sdk`, `@perimeter/core`,
TypeScript and Node type definitions available; the built repository already
provides them. Scaffolding does not install dependencies, publish a package or
execute target traffic. Names accept lowercase letters, digits and hyphens;
path traversal, extra segments, device names and existing destination directories
are refused. Existing probes are never overwritten. New files use exclusive
creation; a filesystem failure after directory creation can leave a partial
scaffold to inspect manually.

## Load it through the CLI

In a scan config with an authorized Target Model:

```yaml
probePaths: [./probes/diagnostics/my-check/dist/probe.js]
include: [diagnostics/my-check]
```

`probePaths` file paths are relative to the scan process's working directory.
The starter chooses one explicitly public, literal REST GET from the model,
uses the guarded client, and records a diagnostic pass only for HTTP 200. It
skips protected/unmodeled routes. This proves wiring, **not security**. Imported
probes are trusted operator code, not sandboxed; review them before scanning.

## Turn the diagnostic into a security probe

Replace its applicability and verdict with one precisely reviewed behavior.
Declare the required identities/capabilities and request budget in the manifest;
keep `plan()` network-free. In `run()`, use the existing guarded transport,
honor cancellation/budget, and attach real captured exchanges to every finding.
Require positive controls and distinguish incomplete evidence from a pass.

Replace the diagnostic tests with vulnerable and patched fixtures for that
behavior, plus missing-control/inconclusive cases. Add a local target/CLI
integration test when the behavior depends on credentials, fixtures, capture,
or lifecycle wiring. The standard [role-access probe](../role-access.md) shows
why a successful HTTP status alone is not authorization evidence.

The empty config schema is a declared authoring contract. The current runtime
does not automatically supply or validate arbitrary per-probe options; do not
add options and imply they are wired without implementing their configuration
path. No new configuration framework is generated for an option-free starter.

Run the generated tests and probe lint again before sharing the probe. See the
[authoring contract](README.md) and [finding schema](../finding-schema.md).
