# Reviewed GraphQL queries

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
The two identities must be modeled and distinct; tenant-scoped queries require
different tenants. Review these semantics yourself: syntax cannot infer who
should be authorized to read a field.

The SDK's `graphqlRequest(endpoint, variables?)` builds a `GuardedRequest` for
custom probes. Send it only through `ctx.http.request`. It sets a 64 KiB response
ceiling. The guard permits POST only for an exact reviewed query on its modeled
origin/path, with a bounded JSON envelope. GET uses `query` and JSON `variables`
parameters. Duplicate/extra parameters, batching, extensions, operation overrides,
mutations, subscriptions, fragments and directives are rejected. Documents are
limited to 8 KiB, 1,000 parser tokens, 50 fields and depth 8. Existing payload
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
