# Contributing

Thanks for your interest. Issues, scanner samples and pull requests are all welcome.

## The most useful contributions

1. **Real scanner output that fhub gets wrong:** a mis-parsed field, a missed duplicate, or a priority that seems off.
   Open an issue with a minimal, **sanitized** sample. See the rules below.
2. **New input formats.** Open an issue first, so we can agree on how the format maps onto the `Finding` model.
3. **Docs and examples** for your CI system.

## Development

Requires Go (see the version in `go.mod`). No CGO, no other tools.

```bash
go build -o bin/fhub ./cmd/fhub
go test ./...
go vet ./...
gofmt -l .          # must print nothing
```

- **Tests never touch the internet:** feeds are served from `testdata/intel` by a local test server. Please keep it
  that way.
- **Layout:** each pipeline stage is its own package under `internal/`: `ingest` → `enrich` → `dedupe` →
  `prioritize` → `policy` → `report`, with `check` wiring them together. See [docs/DESIGN.md](docs/DESIGN.md).

## Test fixtures: no real data

- **Never commit real secrets**, even revoked ones. Use documented dummy values such as AWS's `AKIAIOSFODNN7EXAMPLE`.
- Strip internal hostnames, repository names, file paths and anything else that identifies your organization.

## Pull requests

- Keep each PR focused on one change, and include tests.
- Use [Conventional Commits](https://www.conventionalcommits.org/) titles: `feat:`, `fix:`, `docs:`, `chore:`, …
  PRs are squash-merged, so the PR title becomes the commit message.
- CI must be green: tests on Linux, macOS and Windows, plus the Action self-test.
- By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).

## Security issues

Please don't open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
