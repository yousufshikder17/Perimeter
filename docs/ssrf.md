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
