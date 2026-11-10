# Releasing

1. Make sure `main` is green.
2. Tag and push:
   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
3. `.github/workflows/release.yml` then:
   - runs the tests
   - builds linux/macOS/windows × amd64/arm64 with GoReleaser (`-trimpath`, reproducible timestamps)
   - writes an SPDX SBOM per archive
   - signs `checksums.txt` keylessly with Sigstore cosign
   - adds GitHub build-provenance attestations (public repos only)
   - runs `release-smoke.yml` against the published release: cosign signature, checksums, provenance, and the
     Action installing the real binary on Linux, macOS and Windows. To re-run it by hand:
     `gh workflow run release-smoke.yml -f tag=vX.Y.Z`

Tags with a suffix (`v0.2.0-rc.1`) are published as pre-releases.

Dry run locally (no publish, no signing):

```bash
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=sign,sbom
```

## Verifying a release

`checksums.txt` lists the SHA-256 of every archive and is signed by the release workflow's GitHub OIDC identity:

```bash
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/DaniBenn/findings-hub/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

sha256sum --ignore-missing -c checksums.txt
```

Build provenance (public releases):

```bash
gh attestation verify fhub_0.1.0_linux_amd64.tar.gz --repo DaniBenn/findings-hub
```
