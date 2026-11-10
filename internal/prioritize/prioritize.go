// Package prioritize turns severity + exploit intelligence into an action
// priority (P0..P4) with human-readable reasons.
package prioritize

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// Config holds tunable thresholds. Policy files override these.
type Config struct {
	// EPSSP0 is the EPSS score at/above which a high+ finding becomes P0.
	EPSSP0 float64
	// EPSSP1 is the EPSS score at/above which any finding becomes at least P1.
	EPSSP1 float64
	// DowngradeDev lowers dev-only dependencies by one priority level.
	DowngradeDev bool
}

// DefaultConfig returns the documented defaults (see docs/DESIGN.md §5).
func DefaultConfig() Config {
	return Config{EPSSP0: 0.4, EPSSP1: 0.1, DowngradeDev: true}
}

// Apply sets Priority and Reasons on every finding, in place.
func Apply(fs []model.Finding, cfg Config) {
	for i := range fs {
		fs[i].Priority, fs[i].Reasons = Assess(fs[i], cfg)
	}
}

// Assess computes the priority of one finding and explains why.
func Assess(f model.Finding, cfg Config) (model.Priority, []string) {
	var reasons []string
	p := model.P4

	switch {
	case f.Kind == model.KindSecret:
		p = model.P0
		reasons = append(reasons, fmt.Sprintf("hard-coded secret (%s): rotate it, removing it from code is not enough", f.RuleID))
	case f.KEV != nil:
		p = model.P0
		r := "in CISA KEV: actively exploited in the wild"
		if f.KEV.DateAdded != "" {
			r += " (added " + f.KEV.DateAdded + ")"
		}
		if f.KEV.Ransomware {
			r += ", used in ransomware campaigns"
		}
		reasons = append(reasons, r)
	case f.EPSS != nil && f.EPSS.Score >= cfg.EPSSP0 && f.Severity >= model.SeverityHigh:
		p = model.P0
		reasons = append(reasons, fmt.Sprintf("EPSS %.0f%% chance of exploitation in 30 days and severity %s", f.EPSS.Score*100, f.Severity))
	case f.EPSS != nil && f.EPSS.Score >= cfg.EPSSP1:
		p = model.P1
		reasons = append(reasons, fmt.Sprintf("EPSS %.0f%% chance of exploitation in 30 days", f.EPSS.Score*100))
	case f.Severity == model.SeverityCritical:
		p = model.P1
		reasons = append(reasons, "critical severity")
	case f.Severity == model.SeverityHigh:
		p = model.P2
		reasons = append(reasons, "high severity")
	case f.Severity == model.SeverityMedium:
		p = model.P3
		reasons = append(reasons, "medium severity")
	case f.Severity == model.SeverityUnknown:
		p = model.P3
		reasons = append(reasons, "severity unknown: review manually")
	default:
		reasons = append(reasons, f.Severity.String()+" severity")
	}

	if f.EPSS != nil && p > model.P1 {
		reasons = append(reasons, fmt.Sprintf("EPSS %.1f%% (low exploitation likelihood)", f.EPSS.Score*100))
	}

	if cfg.DowngradeDev && f.Package != nil && f.Package.Scope == "dev" && f.Kind != model.KindSecret && f.KEV == nil && p < model.P4 {
		p++
		reasons = append(reasons, "dev-only dependency: lowered one level")
	}

	if f.Kind == model.KindVuln && f.Package != nil {
		if f.Package.FixedVersion != "" {
			reasons = append(reasons, "fix available: upgrade to "+f.Package.FixedVersion)
		} else {
			reasons = append(reasons, "no fix available yet")
		}
	}
	if len(f.Sources) > 1 {
		names := make([]string, 0, len(f.Sources))
		for _, s := range f.Sources {
			if !slices.Contains(names, s.Scanner) {
				names = append(names, s.Scanner)
			}
		}
		if len(names) > 1 {
			reasons = append(reasons, "confirmed by "+strings.Join(names, " + "))
		}
	}
	return p, reasons
}

// Sort orders findings most-urgent first: priority, severity, CVSS, ID.
func Sort(fs []model.Finding) {
	slices.SortStableFunc(fs, func(a, b model.Finding) int {
		return cmp.Or(
			cmp.Compare(a.Priority, b.Priority),
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(b.CVSS, a.CVSS),
			cmp.Compare(displayID(a), displayID(b)),
		)
	})
}

func displayID(f model.Finding) string {
	if f.VulnID != "" {
		return f.VulnID
	}
	return f.RuleID
}
