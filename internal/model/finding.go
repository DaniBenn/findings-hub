// Package model defines the normalized Finding that every scanner's output is
// converted into. Everything downstream (dedupe, prioritize, policy, report)
// works only with these types and never with scanner-specific formats.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Kind is the broad category of a finding.
type Kind string

const (
	KindVuln   Kind = "vuln"   // vulnerable dependency (SCA / image scanning)
	KindCode   Kind = "code"   // SAST finding in first-party code
	KindSecret Kind = "secret" // hard-coded credential
	KindIaC    Kind = "iac"    // infrastructure-as-code / config misconfiguration
)

// Finding is one normalized, possibly merged, security finding.
type Finding struct {
	// Fingerprint is a stable identifier used for dedupe, baselines and
	// suppressions. Set by the dedupe package.
	Fingerprint string `json:"fingerprint"`
	Kind        Kind   `json:"kind"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	// RuleID is the scanner rule for code/secret/iac findings.
	RuleID string `json:"rule_id,omitempty"`
	// VulnID is the canonical vulnerability ID (CVE preferred), Aliases the rest.
	VulnID  string   `json:"vuln_id,omitempty"`
	Aliases []string `json:"aliases,omitempty"`

	Package  *Package  `json:"package,omitempty"`
	Location *Location `json:"location,omitempty"`

	Severity Severity `json:"severity"`
	CVSS     float64  `json:"cvss,omitempty"`
	URL      string   `json:"url,omitempty"`

	EPSS *EPSS `json:"epss,omitempty"`
	KEV  *KEV  `json:"kev,omitempty"`

	Priority Priority `json:"priority"`
	Reasons  []string `json:"reasons,omitempty"`

	Sources []Source `json:"sources"`

	// MatchHash is a SHA-256 of the matched content (normalized code line or
	// secret value). It feeds fingerprinting so findings survive line moves.
	// Raw secret values are NEVER stored anywhere in a Finding.
	MatchHash string `json:"-"`
}

// Package identifies an affected dependency.
type Package struct {
	Ecosystem    string `json:"ecosystem,omitempty"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	PURL         string `json:"purl,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
	// Scope is "prod", "dev" or "" when unknown.
	Scope string `json:"scope,omitempty"`
}

// Location points at where a finding was observed.
type Location struct {
	Path      string `json:"path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	// Artifact is the scanned target (image name, lockfile, directory).
	Artifact string `json:"artifact,omitempty"`
}

// Source records one scanner that reported this finding.
type Source struct {
	Scanner  string `json:"scanner"`
	Version  string `json:"version,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	Severity string `json:"severity,omitempty"` // as the scanner reported it
	File     string `json:"file,omitempty"`     // input file it came from
}

// EPSS is FIRST's Exploit Prediction Scoring System data for a CVE.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date,omitempty"`
}

// KEV is CISA Known Exploited Vulnerabilities catalog data for a CVE.
type KEV struct {
	DateAdded  string `json:"date_added,omitempty"`
	DueDate    string `json:"due_date,omitempty"`
	Ransomware bool   `json:"known_ransomware_use,omitempty"`
}

// HashContent returns a hex SHA-256 of whitespace-normalized content, or ""
// for empty input. Use it for anything that might be sensitive.
func HashContent(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
