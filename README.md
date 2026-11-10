# findings-hub (working name)

> Feed it every security scanner's output. Get back the handful of findings that matter,
> a CI gate people don't turn off, and an audit trail of everything you decided to accept.

`fhub` doesn't scan your code: it **decides**. It ingests results from Trivy, Grype, Semgrep,
gitleaks, Checkov and anything that speaks SARIF, then:

- **normalizes** them into one model,
- **enriches** them with real-world exploit data (FIRST EPSS, CISA KEV, OSV),
- **deduplicates** overlapping findings across scanners,
- **prioritizes** them P0–P4, with a human-readable reason for every decision,
- **gates** CI on policy, with expiring suppressions, baselines and OpenVEX output.

Single binary. Offline-capable. No telemetry.

## Quick start

```bash
go build -o bin/fhub ./cmd/fhub

trivy fs --format json -o trivy.json .
grype dir:. -o json > grype.json
semgrep scan --sarif -o semgrep.sarif

fhub check trivy.json grype.json semgrep.sarif --fail-on P0,P1
```

Exit codes: `0` passed · `1` security gate failed · `2` error.
Formats: `--format table|json|markdown`.

### Why is this P0?

```bash
fhub explain CVE-2021-44228 trivy.json grype.json   # full reasoning, sources, exploit data
fhub explain CVE-2024-3094                          # quick KEV/EPSS lookup, no scan needed
```

### GitHub Action

```yaml
- run: trivy fs --format json -o trivy.json .
- uses: DaniBenn/findings-hub@v0  # pin to a commit SHA in production
  with:
    files: trivy.json semgrep.sarif
    fail-on: P0,P1
```

The action downloads a checksum-verified release, caches the exploit data daily, and writes a Markdown summary to the job page.

### Policy, suppressions and baselines

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
```

Expired suppressions stop working. A baselined finding that later lands in CISA KEV fails the gate again.

### Exploit intelligence

`fhub check` downloads and caches CISA KEV and FIRST EPSS (about 5 MB, refreshed at most daily) and resolves
GHSA-style advisory IDs to CVEs through OSV. For air-gapped or reproducible runs:

```bash
fhub db update          # fetch feeds (online)
fhub db status          # what is cached and how old it is
fhub --offline check …  # never touch the network
```

If no exploit data is available, `check` fails instead of silently ranking by severity alone.
Use `--no-enrich` to opt out on purpose.

**Status:** pre-alpha, under active development. See [docs/DESIGN.md](docs/DESIGN.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
