# Resumable local scans

Add `checkpoint: scan.checkpoint.json` to a scan config before its first run.
Run `perimeter scan --config scan.yaml`; after interruption, use the same config
with `perimeter scan --config scan.yaml --resume` (or set `resume: true`).
An existing checkpoint is never overwritten by a fresh scan. Archive it and use
a new path to start over. The parent directory must exist.

Completed probes retain their findings, passes, and skips. An interrupted probe
starts again, without retaining its partial reports. The scan ID, seed, original
start time, and global request usage survive. Reservations are persisted before
traffic, so failed/aborted requests can consume budget without producing an audit
entry. They are deliberately not refunded. An exhausted ceiling is not reset on
resume. Per-probe budgets and the wall-clock timeout apply to each attempt.

The engine rechecks authorization on every attempt. The parsed target, config,
probe manifests, baseline acceptance set, and capture settings must match.
Update probe versions when changing their behavior; manifest matching cannot
detect unversioned code changes or changes to a remote target. Credentials are
resolved afresh, never stored in the checkpoint. Target/config contents are
represented by a hash; saved results contain the same evidence as reports.
Protect this file like an audit artifact, not as an untrusted import or a signed
attestation. Keep the original audit log alongside it; a checkpoint cannot
reconstruct missing audit entries. Legacy audit-only scans cannot be resumed.

Only read-only probes may use checkpoints; mutating replay is rejected. Scratch
fixtures for unfinished probes are newly provisioned, not resurrected. Normal
teardown remains best-effort; after a hard crash, inspect the audit trail and
clean up orphaned scratch objects before resuming. This is probe-boundary resume,
not instruction-level replay or exactly-once fixture creation.

Writes use an exclusive lock and flushed temporary file replaced atomically on
the same filesystem. Use a local filesystem supporting atomic replacement.
A hard crash can leave `scan.checkpoint.json.lock`; remove only that lock after
confirming no scan is using it. Never run two copies against one checkpoint.
Malformed, missing, incompatible, or unwritable state fails closed.

<!-- ponytail: snapshots rewrite completed evidence per reservation; switch to a
versioned append-only checkpoint journal if large scans make this measurable. -->
