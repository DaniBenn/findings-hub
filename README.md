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

**Status:** pre-alpha, under active development. See [docs/DESIGN.md](docs/DESIGN.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
