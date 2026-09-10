# Mass-assignment checks

`mass-assignment/protected-field` checks one explicitly reviewed top-level JSON
field per PATCH endpoint, using disposable engine-created records only. It is
part of the local standard library, not a premium service.

Select `include: [mass-assignment]` and pass `--allow-mutating` (or set
`allowMutating: true` in the scan config). Without opt-in the probe is skipped
before fixture provisioning. Authorization and production confirmation still
apply. Write probes execute sequentially after read-only probes and cannot run
with checkpoints/resume. This is not an arbitrary-field fuzzer.

Add these endpoints to an authorized Target Model with identity `owner`:

```yaml
endpoints:
  - id: createNote
    method: POST
    path: /notes
    creates: note
    fixture:
      body: { label: initial, approved: false }
  - id: readNote
    method: GET
    path: /notes/{id}
    objectRef: { param: id, kind: note, ownership: user }
  - id: updateNote
    method: PATCH
    path: /notes/{id}
    objectRef: { param: id, kind: note, ownership: user }
    massAssignment:
      identity: owner
      readEndpointId: readNote
      resultIdPath: [id]
      control: { field: label, value: checked, resultPath: [label] }
      protected: { field: approved, value: true, resultPath: [approved] }
  - id: deleteNote
    method: DELETE
    path: /notes/{id}
    objectRef: { param: id, kind: note, ownership: user }
```

The operator must confirm `approved` is forbidden for this principal, that the
chosen value is valid but harmless on this disposable record, and that changes
have no external effects. Do not model live accounts, permissions, ownership,
payment execution, notification triggers, or records with business side effects.
Use a dedicated scratch-only resource kind when running multiple families.

Each check reads the initial state, PATCHes the allowed control field, reads
that control back, PATCHes the control plus protected field, and reads again.
The same scratch ID must be captured on every GET. Merely echoing a protected
value in the PATCH response is not evidence of persistence. A persisted change
is HIGH/FIRM even if the PATCH returns an error; field policy and impact still
need human confirmation.

A pass requires the ordinary control to persist and the protected field to stay
unchanged after a synchronous 200/204 response or explicit 400/403/422 rejection.
Pre-existing desired values, failed controls, unexpected transformations,
202/asynchronous updates, missing fields, cached responses with positive Age,
and incomplete/redacted evidence are inconclusive. This contract requires an
authoritative read-your-writes GET; requests ask caches not to reuse responses.
No guarantee is made for eventually consistent targets or delayed side effects.

All responses are bounded to 16 KiB; proof uses complete captured JSON. Fields
are top-level string/number/boolean assignments; result paths are literal JSON
keys (including array indices), never executable expressions. Nested writes,
PUT/create-time binding and GraphQL mutations are outside this profile.

A unique POST factory, same-kind GET and DELETE cleanup route are mandatory.
The guard checks method, exact target URL, object kind and engine-tracked ID;
claiming a scratch ID while addressing another object is blocked. Normal HTTP
budgets, rate limits, payload inspection, redaction and cancellation still apply.
Five probe requests are needed, with one additional request of budget headroom.
Authentication/other fixtures also consume the shared budget. Cleanup is
best-effort; cancellation, server errors or exhausted budgets can leave scratch
records. Inspect warnings and remove leftovers manually. The probe does not
restore fields because the entire disposable record is deleted by the engine.

Remediation: use update DTOs/schemas that allow-list writable properties and
authorize protected changes separately. See the
[OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html).
