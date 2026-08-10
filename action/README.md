# Perimeter Scan — GitHub Action

First-class CI/CD integration (spec §8.6). Runs a scan against a deployed
preview/staging target, applies a severity gate (exit code), uploads SARIF for
inline PR annotations, and archives the Markdown/JSON/audit artifacts. Combine
with a baseline so accepted findings don't break the build.

## Usage

```yaml
# .github/workflows/security.yml
name: security
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required for SARIF upload / inline annotations

jobs:
  perimeter:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ... deploy your app to an ephemeral staging/preview target here ...

      - uses: perimeter/perimeter/action@v0
        with:
          config: perimeter.scan.yaml
          fail-on: HIGH
          seed: ${{ github.sha }}
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `config` | `perimeter.scan.yaml` | Scan config path (spec §4). |
| `fail-on` | `HIGH` | Gate severity: `CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO\|none`. |
| `seed` | — | Deterministic seed for reproducible runs (spec §4.1). |
| `upload-sarif` | `true` | Upload SARIF to GitHub code scanning. |
| `version` | `latest` | `@perimeter/cli` version to run. |

The integration interface is deliberately generic; GitLab/Jenkins plugins are
sequenced next (spec §8, §10).
