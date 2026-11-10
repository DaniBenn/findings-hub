package report

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// Explain writes everything fhub knows about one finding and why it got its
// priority. This is the "show your work" view that makes rankings trustable.
func Explain(w io.Writer, f model.Finding) {
	line := func(label, value string) {
		if value != "" {
			fmt.Fprintf(w, "  %-13s %s\n", label+":", value)
		}
	}

	fmt.Fprintf(w, "%s  %s  %s\n", priLabel(f), ID(f), f.Title)
	fmt.Fprintln(w, strings.Repeat("─", 72))
	line("Kind", string(f.Kind))
	line("Aliases", strings.Join(f.Aliases, ", "))
	sev := f.Severity.String()
	if f.CVSS > 0 {
		sev += fmt.Sprintf(" (CVSS %.1f)", f.CVSS)
	}
	line("Severity", sev)
	if p := f.Package; p != nil {
		pkg := p.Name
		if p.Version != "" {
			pkg += "@" + p.Version
		}
		if p.Ecosystem != "" {
			pkg += " [" + p.Ecosystem + "]"
		}
		if p.Scope != "" {
			pkg += " (" + p.Scope + ")"
		}
		line("Package", pkg)
		fix := p.FixedVersion
		if fix == "" && f.Kind == model.KindVuln {
			fix = "none available yet"
		}
		line("Fixed in", fix)
	}
	if l := f.Location; l != nil {
		loc := l.Path
		if l.StartLine > 0 {
			loc += fmt.Sprintf(":%d", l.StartLine)
		}
		line("Location", loc)
		line("Artifact", l.Artifact)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Exploit intelligence")
	switch {
	case f.Kind != model.KindVuln:
		fmt.Fprintln(w, "    n/a (not a dependency vulnerability)")
	default:
		if k := f.KEV; k != nil {
			s := "YES, in CISA KEV (added " + orDash(k.DateAdded)
			if k.DueDate != "" {
				s += ", federal remediation due " + k.DueDate
			}
			s += ")"
			if k.Ransomware {
				s += ", known ransomware use"
			}
			fmt.Fprintln(w, "    Exploited:   "+s)
		} else {
			fmt.Fprintln(w, "    Exploited:   not in CISA KEV")
		}
		if e := f.EPSS; e != nil {
			fmt.Fprintf(w, "    EPSS:        %s%% chance of exploitation in 30 days (percentile %.3f, scored %s)\n",
				strconv.FormatFloat(math.Round(e.Score*100_000)/1000, 'f', -1, 64), e.Percentile, orDash(e.Date))
		} else {
			fmt.Fprintln(w, "    EPSS:        no score (no CVE, or intelligence disabled)")
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Why %s\n", f.Priority)
	for _, r := range f.Reasons {
		fmt.Fprintln(w, "    - "+r)
	}
	if s := f.Suppression; s != nil {
		fmt.Fprintf(w, "    - suppressed until %s: %s\n", s.Expires, s.Reason)
		if s.VEXStatus != "" {
			fmt.Fprintf(w, "      VEX: %s / %s\n", s.VEXStatus, orDash(s.VEXJustification))
		}
	}
	if f.Status == model.StatusBaselined {
		fmt.Fprintln(w, "    - in the baseline: does not fail the gate unless it escalates")
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Reported by")
	if len(f.Sources) == 0 {
		fmt.Fprintln(w, "    (no scanner: intelligence lookup only)")
	}
	for _, s := range f.Sources {
		v := s.Scanner
		if s.Version != "" {
			v += " " + s.Version
		}
		fmt.Fprintf(w, "    - %s: rule %s, severity %s (%s)\n", v, orDash(s.RuleID), orDash(s.Severity), orDash(s.File))
	}
	fmt.Fprintln(w)
	line("Fingerprint", f.Fingerprint)
	line("More info", f.URL)
	fmt.Fprintln(w)
}
