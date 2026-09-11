# Owned SSRF / webhook destination checks

This profile tests one reviewed destination policy using **two operator-owned
origins**. A normal allowed webhook is not an SSRF finding. A finding requires
an observed callback to the second origin, explicitly declared forbidden by
the application's policy, after an observed allowed callback succeeds.
There are no metadata-service, internal-address, redirect, rebinding, or
third-party callback-service payloads.

## Run the collector locally or manually

```sh
perimeter callbacks serve --out callbacks.ndjson --control-port 9001 --prohibited-port 9002
```

The collector needs no container or hosted service. It creates a new private
receipt file and prints both origins. Existing files are refused, not erased.
It stops after one hour (configure `--duration-seconds`, at most one day) or
Ctrl-C. The file remains for evidence review. Each listener accepts only
GET/HEAD/POST at `/perimeter-callback/<32-lowercase-hex-token>`, returning 204
after appending a minimal receipt. Headers, bodies, credentials, and source
addresses are never recorded. Bounds: 16 KiB incoming body, 8 KiB headers,
32 connections per listener, 5-second timeouts, and 1 MiB receipt file.

For an authorized remote target, expose both listeners through infrastructure
you own, or bind an explicit interface with `--host` and
`--acknowledge-exposure`. Review firewall/routing rules; this is not an
authenticated general-purpose public service. Loopback origins only work if
the target can reach that same host. Docker is optional; if you wrap this
command in any container/runtime, publish both ports and explicitly arrange
receipt-file sharing. Perimeter does not start tunnels or open firewall rules.

A manual/custom collector may append the same trusted NDJSON contract:

```json
{"version":1,"kind":"control","token":"0123456789abcdef0123456789abcdef","observedAt":"2026-09-11T12:00:00.000Z","method":"POST"}
```

Use `kind: prohibited` on the second listener. Do not put receipt files in a
target-writable directory or synthesize receipts from target response text.
They attest incoming traffic and are only as trustworthy as your collector.

## Reviewed target contract

Model a disposable factory (`POST /webhooks`, `creates: webhook`) and cleanup
(`DELETE /webhooks/{id}` with the same `objectRef`) alongside this endpoint:

```yaml
- id: dispatchWebhook
  method: POST
  path: /webhooks/{id}/test
  objectRef: { param: id, kind: webhook, ownership: user }
  webhook:
    identity: owner
    urlField: callbackUrl
    body: { event: perimeter-canary }
    controlOrigin: http://127.0.0.1:9001
    prohibitedOrigin: http://127.0.0.1:9002
    receiptFile: callbacks.ndjson
    iOwnBothDestinations: true
    prohibitedByPolicy: true
    timeoutMs: 2000
```

The two origins must differ. `prohibitedByPolicy` is your reviewed assertion,
not a policy Perimeter infers. Both destinations must be harmless, owned
canary listeners; do not point either at sensitive services. The body is fixed,
non-secret JSON; `urlField` must be absent so only the engine-issued URL is added.
POST/PATCH is supported only on the exact engine-created scratch object route.

`receiptFile` is relative to the Target Model file, not the current directory.
Start the collector first. The engine snapshots the existing file, generates
fresh unpredictable 128-bit tokens independently of the scan seed, and only
accepts matching receipts appended afterward. Truncation, replacement, invalid
records, and size-limit failures are errors, never successful blocking checks.
Incoming receipt evidence has `direction: incoming`, empty captured headers/body,
and the collector's 204 acceptance status; target requests remain separately
audited. Custom collectors must use that acceptance contract and synchronized
timestamps. Receipt-file access is a trusted local capability, not a remote API.
