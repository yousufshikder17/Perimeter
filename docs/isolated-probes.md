# Isolated probes: portable protocol v1

Docker is the first container runner, not part of the probe protocol. Workers
exchange newline-delimited JSON over stdin/stdout. A worker can be written in
any language, packaged in a Linux container, launched by an operator-owned
wrapper, or run as a trusted local process. Supporting this protocol is a
portable integration point, not a guarantee that every container product has
already been tested.

## Choose the security boundary

- Normal `probePaths` modules run in-process and are **trusted operator code**.
  Importing them executes their module. A linter and TypeScript interfaces do
  not sandbox malicious JavaScript. Never put an untrusted module there.
- `isolatedProbes` are declared as data. The host never imports worker code.
  The container runner delegates OS isolation to the selected runtime.
- The command runner is explicitly operator-managed. It can launch a trusted
  local process or a wrapper around another sandbox, VM, or already-running
  worker. Perimeter cannot verify that wrapper's isolation guarantees.

An `isolation: subprocess` manifest alone is not sufficient; the engine refuses
to execute it unless it came from the declarative worker adapter. Ordinary
scans do not need Docker. There is no automatic fallback from containers to
unsandboxed execution.

## Container runner

Build the diagnostic example explicitly before scanning:

```sh
docker build -t perimeter-worker:local examples/isolated-probe
```

Add this to a scan configuration:

```yaml
isolatedProbes:
  - manifest:
      id: diagnostics/worker
      family: diagnostics
      version: "1"
      schemaVersion: "1"
      requires: {}
      safety: { class: read-only, maxRequests: 1, destructive: false }
    timeoutSeconds: 60
    runner:
      kind: container
      runtime: docker
      image: perimeter-worker:local
include: [diagnostics/worker]
```

`runtime` is an executable, defaulting to `docker`. A compatible CLI such as
Podman can be selected there, but must support the exact create/start/remove
flags. Other runtimes use the command runner below. An optional `command` array
is passed as the image command; it cannot add runtime options or host mounts.
Image names cannot start with an option prefix. Images are never pulled
automatically; operators should build/review them and pin digests for CI.

The fixed Linux-container profile uses no network, a read-only root filesystem,
UID/GID 65532, no Linux capabilities, no-new-privileges, 64 PIDs, 256 MiB RAM
with no additional swap allowance, one CPU, and a 16 MiB noexec tmpfs at `/tmp`.
It provides no host mounts, Docker socket, forwarded credentials, published
ports, or health checks. Runtime logging is disabled. If the runtime rejects a
restriction, Perimeter does not retry with weaker flags. Operators must verify
that their runtime and host actually enforce the profile. This is not a Windows-container
profile. Keep the runtime/kernel patched and use a trusted daemon configuration;
containers are not a promise against kernel or runtime vulnerabilities.

The runner creates a uniquely named container, then attaches stdin/stdout when
starting it. It attempts force-removal of that exact container and its anonymous
volumes on completion, error, or cancellation. Cleanup failure fails the scan and
names the container to inspect. A host crash or unavailable daemon can still
require operator cleanup; Perimeter never prunes unrelated containers.

See the runtime contracts in the [Docker run/create options](https://docs.docker.com/reference/cli/docker/container/run/)
and [Podman run options](https://docs.podman.io/en/latest/markdown/podman-run.1.html).
Docker is the initial runner; live Docker verification requires a working daemon.
Podman compatibility has not been integration-tested in this workspace.

After building the example image and starting the daemon, enable the opt-in
container regression test with `PERIMETER_TEST_DOCKER=1` and run
`pnpm exec vitest run packages/core/src/isolation/probe.test.ts` after `pnpm build`.
The ordinary suite exercises real local workers and verifies the fixed container
arguments without requiring a daemon; it does not substitute for this live test.

## Trusted local execution and manual/custom launchers

Use the same manifest with:

```yaml
runner:
  kind: command
  command: [node, examples/isolated-probe/worker.mjs]
  acknowledgeExternalSecurity: true
```

Arguments are an array and are never shell-expanded. The process receives only
OS bootstrap environment variables (`PATH`, `PATHEXT`, `SYSTEMROOT`, `WINDIR`,
`TEMP`, `TMP`), not the parent credential environment. This is **not a sandbox**:
a trusted local process still has its OS user's filesystem and network rights.
Only the direct process is terminated; wrappers must own descendant cleanup.

For another runtime, set `command` to your launcher and its arguments. For a
manually created worker, that launcher can attach/relay stdin and stdout to it.
The operator must enforce no network/host-secret access and resource limits,
handle disconnects and cleanup, and arrange runtime configuration explicitly.
Perimeter does not discover, adopt, or delete manually owned containers.
You may also start the example directly in a terminal and exchange protocol
frames manually for debugging; it has no target access until a parent services
its request messages. No always-on broker, socket, or hosted service is needed.

## Wire contract

Protocol v1 adapts the standard lifecycle: the host's `plan()` supplies a bounded
worker step; only `run()` launches external code. This is not a transparent
serialization of arbitrary existing TypeScript `Probe` objects. Workers use the
wire contract below instead of importing credentials or a raw target client.

The parent sends one `start` frame:

```json
{"type":"start","version":1,"probeId":"diagnostics/worker","seed":"123","target":{"name":"test","baseUrl":"http://localhost:8080","tenancy":{},"endpoints":[],"identities":[]},"fixtures":[],"budget":{"limit":1,"remaining":1}}
```

The real target snapshot includes modeled endpoint annotations, tenancy,
permitted identity refs/roles, and provisioned fixtures belonging to those
identities. It omits the auth recipe, credential environment references, and
fixture request payloads. Identity access is limited to `manifest.requires.identities`.
The seed is deterministically derived from the scan's per-probe RNG.

A worker requests a read:

```json
{"type":"request","id":0,"request":{"method":"GET","url":"/profile","as":"tenantA.user"}}
```

IDs are increasing nonnegative integers. Methods are GET, HEAD, or OPTIONS.
Headers may include Accept, Content-Type, and the modeled non-sensitive tenant
discriminator header. Host, credential, forwarding, and framing header overrides
are not allowed. Optional `jwtVariant` uses the existing engine-owned JWT checks;
it never exposes credentials. The parent applies normal host, identity, payload,
rate, request-budget, and audit controls, plus a 1 MiB response limit. Successful
replies contain only the parent's sanitized, capture-bounded `HttpExchange`:

```json
{"type":"response","id":0,"ok":true,"exchange":{"ref":"sha256:...","request":{"method":"GET","url":"http://localhost:8080/profile","headers":{}},"response":{"status":200,"headers":{},"body":"{}"}},"remaining":0}
```

Denied/failed requests return `ok: false`, a generic error, and the remaining
budget. Authentication errors fail the scan. Credential exchanges remain
engine-owned and subject to the scan deadline; worker cancellation prevents a
pending authenticated probe request from being sent after credentials resolve.

A worker can submit a finding using observed exchange references:

Reviewed read-only unary RPCs use the same increasing request-ID sequence:

```json
{"type":"grpc-request","id":1,"request":{"endpointId":"readRecord","as":"owner"}}
```

The host supplies the modeled method, proto, origin, and fixed payload; the
worker may only select an endpoint, permitted identity, and optional owned
`scratchObjectId`. The reply uses `type: response` with a native gRPC `code`
and sanitized `exchange` whose `protocol` is `grpc`. A completed RPC with a
nonzero status is still `ok: true`; `ok` indicates transport invocation, not
authorization success. Deadlines, cancellation, budgets, and evidence-reference
validation remain host-owned. See [gRPC checks](grpc.md).

Findings attach those host-observed references, for either transport:

```json
{"type":"finding","endpointId":"profile","locator":"missing-auth","title":"Possible missing authentication","severity":"HIGH","confidence":"FIRM","summary":"Review whether the anonymous response contains protected data.","exchangeRefs":["sha256:..."],"remediation":{"guidance":"Require authentication on protected routes.","references":[]}}
```

The host supplies the finding ID, fingerprint, timestamps, target, identities,
and actual recorded evidence. Unknown references and unmodeled endpoints fail
the scan. A worker cannot submit replacement HTTP evidence or choose an accepted
finding status. It remains responsible for honest vulnerability semantics; an
isolated worker can still make an incorrect claim about real observations.

An explicit diagnostic/pass uses `type: pass`, `endpointId`, `title`, and
`summary`; it requires observed traffic. Finish with:

```json
{"type":"done","version":1}
```

Then exit zero. Stdout is protocol-only. Stderr is drained but not persisted.
Invalid frames, unknown fields, duplicate request IDs, missing completion,
nonzero exit, and timeouts fail the scan, not merely skip a probe. Bounds are
256 KiB per frame, 8 MiB worker stdout, 64 KiB stderr, 10,000 messages, 100 reports,
the manifest/global request budgets, and a 1–3600 second worker deadline (default
60), also bounded by scan cancellation. Workers should request/await serially.
