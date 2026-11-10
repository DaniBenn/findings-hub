# fhub

[![ci](https://github.com/DaniBenn/findings-hub/actions/workflows/ci.yml/badge.svg)](https://github.com/DaniBenn/findings-hub/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/DaniBenn/findings-hub?sort=semver)](https://github.com/DaniBenn/findings-hub/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Your scanners found 400 issues. fhub tells you which 6 are being exploited.**

fhub doesn't scan your code; it **decides**. Feed it the output of Trivy, Grype, Semgrep, gitleaks, Checkov or anything
that speaks SARIF, and it:

- **merges duplicates** across scanners (Trivy's `CVE-2021-23337` and Grype's `GHSA-35jh-r3h4-6jhm` are one issue),
- **ranks by real-world exploitation**, using [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
  [FIRST EPSS](https://www.first.org/epss/) rather than severity alone,
- **explains every decision** in plain language,
- **gates CI** with a policy people don't switch off: expiring suppressions, and baselines that re-alert when an old issue
  starts being exploited.

Single static binary · works offline · no telemetry · signed releases with SBOMs.

```
$ fhub check trivy-fs.json grype-dir.json semgrep.sarif gitleaks.sarif   # samples in testdata/

PRI  SEVERITY  KIND    ID                            WHERE                                     WHY                                                           SOURCES
P0   critical  vuln    CVE-2021-44228                ….apache.logging.log4j:log4j-core@2.14.1  in CISA KEV: actively exploited in the wild (added 2021-12-…  trivy,grype
P0   critical  secret  aws-access-key-id             config/settings.env:3                     hard-coded secret (aws-access-key-id): rotate it, removing …  trivy,gitleaks
P1   high      vuln    CVE-2021-23337                lodash@4.17.20                            EPSS 21% chance of exploitation in 30 days                    trivy,grype
P2   high      iac     AVD-DS-0002                   Dockerfile                                high severity                                                 trivy
P2   high      code    …it.sqli.jdbc-sqli.jdbc-sqli  src/main/java/com/demo/UserRepo.java:42   high severity                                                 semgrep
P3   medium    vuln    CVE-2020-28500                lodash@4.17.20                            medium severity                                               trivy
P3   medium    vuln    CVE-2022-25883                semver@7.5.1                              medium severity                                               grype
P4   low       code    …dit.weak-random.weak-random  src/main/java/com/demo/Token.java:12      low severity                                                  semgrep

8 unique findings from 11 raw (3 duplicates merged) across 4 input(s).  P0:2  P1:1  P2:2  P3:2  P4:1
Exploit intelligence: CISA KEV 2026.11.09, EPSS 2026-11-09.
fhub: security gate FAILED: 2 finding(s) at P0
```

## Install

- **Binaries:** download from [Releases](https://github.com/DaniBenn/findings-hub/releases) (Linux, macOS, Windows; amd64/arm64).
  Each release is signed; see [verifying a release](docs/RELEASING.md#verifying-a-release).
- **Go:** `go install github.com/DaniBenn/findings-hub/cmd/fhub@latest`
- **GitHub Actions:** see [below](#github-action).

## Quick start

```bash
trivy fs --format json -o trivy.json .
grype dir:. -o json > grype.json
semgrep scan --sarif -o semgrep.sarif

fhub check trivy.json grype.json semgrep.sarif --fail-on P0,P1
```

Exit codes: `0` passed · `1` security gate failed · `2` error.
Formats: `--format table|json|markdown`, plus `--report-json` / `--report-markdown` for extra outputs in the same run.

| Input | Notes |
|---|---|
| SARIF 2.1.0 | Semgrep, CodeQL, gitleaks, Checkov, tfsec, KICS, Trivy, … |
| Trivy JSON | vulnerabilities, secrets, misconfigurations |
| Grype JSON | including related CVEs |

## How ranking works

| Priority | Default rule |
|---|---|
| **P0** fix now | in CISA KEV, **or** EPSS ≥ 40% and severity high+, **or** a hard-coded secret |
| **P1** this sprint | EPSS ≥ 10%, **or** critical severity |
| **P2** plan it | high severity |
| **P3** backlog | medium (or unknown) severity |
| **P4** ignore unless cheap | low / info |

Dev-only dependencies drop one level (never when in KEV). Every threshold can be changed in `.fhub.yaml`.

### Why is this P0?

```bash
fhub explain CVE-2021-44228 trivy.json grype.json   # full reasoning, every source, exploit data
fhub explain CVE-2024-3094                          # quick KEV/EPSS lookup, no scan needed
```

## GitHub Action

```yaml
- run: trivy fs --format json -o trivy.json .
- uses: DaniBenn/findings-hub@v0.1.0   # better: pin to the release's commit SHA
  with:
    files: trivy.json semgrep.sarif
    fail-on: P0,P1
```

The Action:
- installs a checksum-verified release
- caches exploit data daily
- writes the report to the job summary
- exposes `result`, `blocking` and `report` outputs; set `fail: "false"` for report-only mode

## Policy, suppressions and baselines

```bash
fhub init                                  # writes a commented .fhub.yaml
fhub baseline create trivy.json grype.json # accept today's findings on a legacy codebase
fhub check trivy.json grype.json --new-only
```

```yaml
suppressions:
  - id: CVE-2021-23337
    package: pkg:npm/lodash
    reason: "We never call _.template(); not reachable."
    expires: 2027-01-31   # required, max 1 year: no permanent ignores
    vex: { status: not_affected, justification: vulnerable_code_not_in_execute_path }
```

- Expired suppressions stop working and say why.
- Typos in the policy file are errors, not silent no-ops.
- **A baselined finding that later lands in CISA KEV fails the gate again**, so a baseline never hides an issue that
  started being exploited after you accepted it.

## Exploit intelligence & privacy

`fhub check` downloads and caches CISA KEV and FIRST EPSS (about 5 MB, refreshed at most daily). For findings without a
CVE, it resolves advisory IDs (GHSA, PYSEC, …) through [OSV](https://osv.dev).

- **The only data that leaves your machine** is those public advisory IDs, sent to OSV. Package names, code and file
  paths are never sent. There is no telemetry.
- Secret values are never stored or printed; only a hash is kept, to identify duplicates.
- **Air-gapped / reproducible runs:**
  ```bash
  fhub db update          # fetch feeds (online)
  fhub db status          # what is cached and how old it is
  fhub --offline check …  # never touch the network
  ```
- If no exploit data is available, `check` **fails** rather than silently ranking by severity alone.
  `--no-enrich` opts out on purpose.

## Status & roadmap

**v0.1: early and usable. Feedback is very welcome** ([issues](https://github.com/DaniBenn/findings-hub/issues)).

Next up:
- OpenVEX export of suppressions
- CycloneDX/SPDX SBOM input
- run history (SQLite)
- a local dashboard (`fhub serve`)
- a CI/CD workflow-hardening module

The design is in [docs/DESIGN.md](docs/DESIGN.md).

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
