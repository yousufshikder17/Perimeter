# Reviewed unary gRPC

Perimeter's gRPC contract names one read-only unary RPC and embeds its reviewed,
self-contained proto text. It does not use server reflection, discover methods,
load proto imports from disk/network, or run streaming/mutating RPCs. An RPC's
name does not establish read-only behavior: the operator must review its effects.

```yaml
- id: readRecord
  method: POST
  path: /example.Records/Get
  grpc:
    readOnly: true
    origin: https://api.example.test:443
    proto: |
      syntax = "proto3";
      package example;
      message Request { string id = 1; }
      message Reply { string id = 1; }
      service Records { rpc Get(Request) returns (Reply); }
    request: { id: reviewed-test-record }
    resultPath: [id]
    ownerIdentity: owner
    otherIdentity: reader
    deadlineMs: 5000
```

This is an endpoint entry inside an authorized Target Model. Both identities
must exist and differ; tenant-scoped endpoints require different tenants.
`origin` defaults to the model's base URL and is an explicit authorization for
that service origin, not a wildcard allow-list. TLS is required outside the
`local` environment. The proto is at most 64 KiB; requests and decoded replies
are bounded to 16 KiB. Field names retain proto spelling. 64-bit integers in
decoded evidence are strings, avoiding JavaScript precision loss.

The SDK request surface selects only an endpoint ID, a modeled identity (or
anonymous), and optionally an engine-created scratch ID. Callers cannot supply
another origin, RPC method, schema or arbitrary payload. These contracts are
the foundation for guarded transport and protected-data authorization checks.

See [gRPC Node basics](https://grpc.io/docs/languages/node/basics/) and
[gRPC deadlines](https://grpc.io/docs/guides/deadlines/) for protocol background.
