package policy

import (
	"strings"
	"time"
)

const template = `# fhub policy. Docs: https://github.com/DaniBenn/findings-hub/blob/main/docs/DESIGN.md
version: 1

gate:
  # Priorities that fail the build. P0 = known/likely exploited, P1 = fix this sprint.
  fail_on: [P0]
  # Adopting fhub on an existing codebase? Snapshot today's findings with
  #   fhub baseline create <scanner-output>...
  # then set new_only: true so only NEW issues fail the build. Baselined issues
  # that escalate (e.g. get added to CISA KEV) fail it again.
  new_only: false
  baseline: .fhub-baseline.json

prioritize:
  # EPSS = probability of exploitation in the next 30 days (0..1).
  epss_p0: 0.4        # high/critical + EPSS >= this -> P0
  epss_p1: 0.1        # any severity + EPSS >= this -> at least P1
  downgrade_dev: true # dev-only dependencies drop one level (never below what KEV says)

# Accepted risk. Every entry needs a reason and an expiry (max 1 year):
# expired suppressions stop working and the finding fails the gate again.
# Matchers (all given ones must match): id (CVE/GHSA/alias or rule ID),
# fingerprint, package (purl, optionally @version, or name), path (glob, ** ok).
suppressions: []
#  - id: CVE-2021-23337
#    package: pkg:npm/lodash
#    reason: "We never call _.template(); the vulnerable code is unreachable."
#    expires: {{EXAMPLE_EXPIRY}}
#    vex:
#      status: not_affected
#      justification: vulnerable_code_not_in_execute_path
#  - id: generic-api-key
#    path: "test/fixtures/**"
#    reason: "Dummy keys used by unit tests."
#    expires: {{EXAMPLE_EXPIRY}}
`

// Template returns the starter policy written by `fhub init`.
func Template(now time.Time) string {
	return strings.ReplaceAll(template, "{{EXAMPLE_EXPIRY}}", now.AddDate(0, 3, 0).Format(time.DateOnly))
}
