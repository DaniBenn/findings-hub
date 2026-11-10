package model

import (
	"fmt"
	"strings"
)

// Severity is a normalized severity. Higher value = more severe.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"unknown", "info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity maps the many spellings scanners use onto Severity.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high", "error":
		return SeverityHigh
	case "medium", "moderate", "warning":
		return SeverityMedium
	case "low", "note":
		return SeverityLow
	case "info", "informational", "negligible", "none":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// SeverityFromCVSS maps a CVSS-style 0-10 score onto Severity using the
// standard CVSS v3 qualitative bands.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	*s = ParseSeverity(string(b))
	return nil
}

// Priority is the computed action priority. P0 is most urgent.
// The zero value means "not yet prioritized".
type Priority int

const (
	PriorityUnset Priority = iota
	P0
	P1
	P2
	P3
	P4
)

func (p Priority) String() string {
	if p < P0 || p > P4 {
		return "unset"
	}
	return fmt.Sprintf("P%d", int(p-P0))
}

// ParsePriority parses "P0".."P4" (case-insensitive).
func ParsePriority(s string) (Priority, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) == 2 && s[0] == 'P' && s[1] >= '0' && s[1] <= '4' {
		return P0 + Priority(s[1]-'0'), nil
	}
	return PriorityUnset, fmt.Errorf("invalid priority %q (want P0..P4)", s)
}

func (p Priority) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

func (p *Priority) UnmarshalText(b []byte) error {
	v, err := ParsePriority(string(b))
	if err != nil {
		return err
	}
	*p = v
	return nil
}
