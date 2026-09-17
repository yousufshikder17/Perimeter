# GitLab and Jenkins integrations

These are reviewed pipeline templates, not platform plugins or a hosted scanner.
Both use the existing CLI through `node ci/run-scan.mjs`. Check out a pinned,
reviewed Perimeter source revision; the packages are not assumed to be published.
The templates install with the frozen lockfile and build before scanning.

Use Node 24 and Corepack/pnpm from the repository packageManager declaration.
The Jenkins `perimeter` agent label must identify a Linux agent with these tools;
GitLab uses a Node image and a runner able to reach your authorized staging target.
Pin container digests according to your organization policy. No Docker daemon is
needed for ordinary scans. Isolated container probes need separately provisioned,
reviewed runners; do not expose a host Docker socket by copying these templates.

## Configuration

Create a reviewed `perimeter.scan.yaml` at the checkout root, or set
`PERIMETER_SCAN_CONFIG` to another path:

```yaml
target: perimeter.target.yaml
seed: reviewed-ci-scan
failOn: HIGH
maxTotalRequests: 500
maxWallClockSeconds: 600
```

Supply your own authorized Target Model; no target is guessed or deployed.
Paths, including probe modules and schema files, retain the scan process's
working-directory semantics. Configure credentials through the Target Model's
environment references. Use protected/masked GitLab variables or narrowly scoped
Jenkins credentials bindings; never hardcode them in YAML, command arguments,
probe options or artifacts. Only trusted branches/jobs may access credentials
or run scans. Production confirmation and mutating opt-ins are not enabled by
these templates; any such use needs separate explicit authorization.

The runner reserves `.perimeter-ci` for its six known output files. It clears
those files before a new scan, refuses symlinked outputs, and leaves unrelated
files alone. Keep configuration, targets, baselines and checkpoints outside this
directory. Configured output paths are overridden so artifact collection stays
predictable. Fresh scans only: checkpoint/resume is rejected. A temporary config
is written with restrictive permissions and removed afterwards, not archived.

## GitLab

Include `ci/gitlab.yml` in `.gitlab-ci.yml` using a local include. Ensure your
pipeline has a `test` stage. The job is manual on protected refs and blocking
(`allow_failure: false`). Adjust this only after reviewing your authorization
and secret-access policy. Reports are collected on success/failure, limited to
Developer access, and expire after seven days. GitLab timeout/cancellation may
prevent collection; see [artifact behavior](https://docs.gitlab.com/ci/jobs/job_artifacts/).
SARIF is downloadable, not converted to GitLab's native security-report schema.

## Jenkins

Configure a trusted Pipeline-from-SCM job to use `ci/Jenkinsfile`. It starts with
a clean job workspace, prevents concurrent builds, and requires approval before
scanning. Install Pipeline and JUnit support. Restrict job configuration, approval,
workspace and artifact access using Jenkins permissions; the template cannot
establish your server's authorization policy.

The `post/always` block archives reports after a failed gate. JUnit is for viewing;
`skipMarkingBuildUnstable` keeps the CLI's configured severity/baseline gate as the
build-status authority. See [Jenkins report steps](https://www.jenkins.io/doc/pipeline/steps/junit/).

## Failure handling and evidence

The runner returns the CLI exit code unchanged (including private inconclusive
coverage codes). A configuration, startup or report-writing error fails the job.
JUnit test failures do not replace Perimeter's severity/baseline decision. Missing
artifacts do not turn a failed scan into success. Audit logs and temporary config
files are intentionally excluded from the artifact allowlist. Findings may still
contain sensitive application evidence: redaction is not permission to publish
them. Restrict artifact access and retention in both platforms.

Repository tests verify template structure, the shared runner, real CLI gate
success/failure, generated report formats, stale-report removal and unsafe-output
refusal. They do not claim a live GitLab/Jenkins deployment was executed; validate
the templates on your own server/version before adopting them.
