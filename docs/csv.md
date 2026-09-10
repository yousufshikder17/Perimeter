# CSV/formula export checks

`csv/formula` is a local standard probe. Select it with `include: [csv]`.
It reads a reviewed GET export through guarded HTTP; the engine first creates
the configured disposable fixture, as with other fixture-based probes.
It never launches a spreadsheet, shell, network formula, or external callback.

Add these endpoints to an authorized Target Model (identity `owner` must exist):

```yaml
endpoints:
  - id: createNote
    method: POST
    path: /notes
    creates: note
    fixture:
      body: { note: '=1+1' }
  - id: exportNotes
    method: GET
    path: /notes/export
    objectRef: { param: id, kind: note, ownership: user }
    csv:
      identity: owner
      column: note
      idColumn: id
      fixtureField: note
  - id: deleteNote
    method: DELETE
    path: /notes/{id}
    objectRef: { param: id, kind: note, ownership: user }
```

The factory's field must exactly match `csv.canary`: `=1+1` (default), `+1+1`,
`-1+1`, or `@SUM(1,1)`. These are harmless arithmetic canaries, not arbitrary
payloads. Use a separate reviewed contract/fixture kind for each desired
variant. Factory validation may reject canaries; that yields no export proof.

`delimiter` defaults to comma; semicolon and tab are supported. Headers are
exact and unique. The probe locates exactly one row using the engine-created
ID, never another user's row. The export path may be literal or contain its
single `{objectRef.param}` placeholder; query strings are excluded.

Evidence is limited to complete, captured `text/csv` responses of at most
16 KiB, 1,000 rows and 128 columns, with strict quoting, BOM and multiline
handling. Missing, redacted, malformed, oversized or ambiguous evidence is
inconclusive, not a pass. Configure small scratch-only exports.

An unchanged formula cell produces MEDIUM/FIRM evidence, including when CSV
quoted. An apostrophe-prefixed exact canary produces a narrowly worded pass
for that prefix observation. Other transformations, including tabs, are
inconclusive: spreadsheet import behavior differs. Neither outcome claims
spreadsheet execution, coverage of all dangerous prefixes, or safe save/reopen
behavior. See [OWASP CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection).

Model cleanup and use disposable data. Fixture setup/cleanup consumes scan
budgets; cleanup remains best-effort and hard interruption can leave fixtures.
This read-only probe supports existing probe-boundary checkpoints.
