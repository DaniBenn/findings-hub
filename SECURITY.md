# Security policy

fhub is a security tool, so we hold it to a higher bar. Thank you for helping.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository
([direct link](https://github.com/DaniBenn/findings-hub/security/advisories/new)).

Please include:
- the affected version (`fhub --version`) and platform
- steps or a minimal input file that reproduces the problem
- the impact as you understand it

What to expect:
- an acknowledgement within **3 business days**
- an assessment and a fix plan within **10 business days**
- a fix released as soon as practical, coordinated with you, with credit in the advisory if you want it

## Supported versions

Until 1.0, only the **latest release** receives security fixes.

## Scope

In scope, for example:
- **Gate bypass:** crafted scanner output or policy that makes a finding that should gate pass silently.
- **Secret leakage:** a secret value appearing in any output, cache or log. fhub is designed never to store secret values.
- **Unsafe network behaviour:** non-HTTPS fetches, sending data other than public advisory IDs, cache poisoning that
  survives the integrity checks.
- **Code execution or path traversal** through input files, policy files or the GitHub Action's inputs.
- **Release integrity:** signature, checksum or provenance problems.

Out of scope:
- Vulnerabilities in the scanners whose output fhub reads, or wrong data in CISA KEV, EPSS or OSV (please report those
  upstream).
- Ranking disagreements that aren't security bugs (please open a normal issue).

## Verifying releases

See [docs/RELEASING.md](docs/RELEASING.md#verifying-a-release).
