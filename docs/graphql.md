# Reviewed GraphQL queries

## Authorization probe

`graphql/authorization` is included in the standard probe library. Select it with
`include: [graphql]` or allow normal capability selection. For each protected
query it sends an owner control, an anonymous comparison, and an other-identity
comparison (up to 60 query requests, with fixture/authentication traffic also
counting against the global ceiling).

With `objectRef`, the variable is filled with an engine-created owner fixture ID,
and the owner response must return that ID at `resultPath`. Without `objectRef`,
this is an explicitly modeled field-authorization comparison. A clean owner
response must expose a non-empty string or finite number at the selected path.
The same captured scalar exposed to anonymous/other access produces HIGH/FIRM
evidence requiring semantic review. Partial responses containing both protected
data and GraphQL errors are still checked for disclosure. An error HTTP status
does not conceal a protected scalar actually present in the captured data.

HTTP 200 alone is never success evidence. Explicit 401/403/404 or a GraphQL
FORBIDDEN/UNAUTHENTICATED rejection without the protected scalar produces a pass
for that comparison. Generic errors, failed owner controls, missing fixtures,
different values, or incomplete/redacted evidence are inconclusive, not passes.
The REST probes exclude GraphQL entries so they cannot mistake GraphQL errors
inside a 200 response for REST authorization failures.

## Target and transport

GraphQL queries reuse Perimeter's guarded HTTP client, credentials, budgets,
rate limiter, audit log, and read-only checkpoint support. No separate client or
service is required. Use the server's supported GET or POST query transport.

```yaml
endpoints:
  - id: invoice-query
    method: POST
    path: /graphql
    auth: required
    tenantScoped: true
    objectRef: { param: id, kind: invoice, ownership: tenant }
    graphql:
      query: 'query Invoice($id: ID!) { invoice(id: $id) { id } }'
      variables: {}
      resultPath: [invoice, id]
      ownerIdentity: tenantB.user
      otherIdentity: tenantA.user
```

Each inventory entry represents one reviewed query, not the whole GraphQL
schema. Multiple entries can share a path. `objectRef.param` names a query
variable; a probe can fill it from the engine's REST-created scratch fixtures.
GraphQL mutations are not fixture factories. Omit `objectRef` for an explicitly
reviewed field-authorization query that needs no object fixture.

`resultPath` is relative to `data` and must identify a protected, distinguishing
scalar (typically an object ID), not a public constant, count, or `__typename`.
Use literal JSON keys and string array indices in the result path.
The two identities must be modeled and distinct; tenant-scoped queries require
different tenants. Review these semantics yourself: syntax cannot infer who
should be authorized to read a field.

The SDK's `graphqlRequest(endpoint, variables?)` builds a `GuardedRequest` for
custom probes. Send it only through `ctx.http.request`. It sets a 64 KiB response
ceiling. The guard permits POST only for an exact reviewed query on its modeled
origin/path, with a bounded JSON envelope. GET uses `query` and JSON `variables`
parameters. Duplicate/extra parameters, batching, extensions, operation overrides,
mutations, subscriptions, fragments and directives are rejected. Documents are
limited to 8,192 UTF-16 code units, 1,000 parser tokens, 50 fields and depth 8. Existing payload
inspection still applies. Keep variables non-secret; URLs and query documents
are evidence. Review resolvers for side effects even when declared as queries.

This is a declarative query adapter, not automatic introspection or a schema
crawler. Full-schema validation, subscriptions, mutation scanning, federation,
persisted queries, and GraphQL-only fixture creation are outside this profile.

Transport follows [GraphQL's HTTP guidance](https://graphql.org/learn/serving-over-http/).
Query syntax is checked with the [reference parser](https://www.graphql-js.org/api-v16/language/), not a mutation-keyword regex.

Probes using target-configured identity pairs can declare `requires.allIdentities:
true`. The engine then provisions each modeled REST factory for every modeled
identity under the shared request ceiling. This explicit manifest capability also
controls which identities an isolated worker receives; it does not grant access
to identities outside the Target Model.
