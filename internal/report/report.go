// Package report renders prioritized findings for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/DaniBenn/findings-hub/internal/enrich"
	"github.com/DaniBenn/findings-hub/internal/model"
)

// SchemaVersion of the JSON output. Bump on breaking changes.
const SchemaVersion = 1

// Summary describes one check run.
type Summary struct {
	Inputs     int            `json:"inputs"`
	Raw        int            `json:"raw_findings"`
	Unique     int            `json:"unique_findings"`
	Merged     int            `json:"duplicates_merged"`
	ByPriority map[string]int `json:"by_priority"`
	GateFailOn []string       `json:"gate_fail_on"`
	GateFailed bool           `json:"gate_failed"`
	Blocking   int            `json:"blocking_findings"`
	Intel      enrich.Info    `json:"intel"`
}

// Report is the full result of a run.
type Report struct {
	SchemaVersion int             `json:"schema_version"`
	Tool          Tool            `json:"tool"`
	Summary       Summary         `json:"summary"`
	Findings      []model.Finding `json:"findings"`
}

// Tool identifies the fhub build that produced the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Formats lists supported output formats.
var Formats = []string{"table", "json", "markdown"}

// Write renders r in the given format.
func Write(w io.Writer, r Report, format string) error {
	switch format {
	case "table":
		return writeTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "markdown", "md":
		return writeMarkdown(w, r)
	default:
		return fmt.Errorf("unknown format %q (want one of %s)", format, strings.Join(Formats, ", "))
	}
}

func writeTable(w io.Writer, r Report) error {
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PRI\tSEVERITY\tKIND\tID\tWHERE\tWHY\tSOURCES")
		for _, f := range r.Findings {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				f.Priority, f.Severity, f.Kind,
				truncLeft(ID(f), 28), truncLeft(Where(f), 40), trunc(firstReason(f), 60), trunc(scanners(f), 24))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, summaryLine(r.Summary))
	return nil
}

func writeMarkdown(w io.Writer, r Report) error {
	s := r.Summary
	status := "✅ **Security gate passed**"
	if s.GateFailed {
		status = fmt.Sprintf("❌ **Security gate failed**: %d blocking finding(s) at %s", s.Blocking, strings.Join(s.GateFailOn, "/"))
	}
	fmt.Fprintf(w, "## Security findings\n\n%s\n\n%s\n\n", status, strings.ReplaceAll(summaryLine(s), "\n", "\n\n"))
	if len(r.Findings) == 0 {
		return nil
	}
	fmt.Fprintln(w, "| Priority | Severity | ID | Where | Why |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
			f.Priority, f.Severity, mdLink(ID(f), f.URL), mdEscape(Where(f)), mdEscape(strings.Join(f.Reasons, "; ")))
	}
	return nil
}

func summaryLine(s Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d unique findings from %d raw (%d duplicates merged) across %d input(s).",
		s.Unique, s.Raw, s.Merged, s.Inputs)
	b.WriteString("  ")
	for i, p := range []string{"P0", "P1", "P2", "P3", "P4"} {
		if i > 0 {
			b.WriteString("  ")
		}
		fmt.Fprintf(&b, "%s:%d", p, s.ByPriority[p])
	}
	b.WriteString("\n")
	b.WriteString(intelLine(s.Intel))
	return b.String()
}

func intelLine(i enrich.Info) string {
	if !i.Enabled {
		return "Exploit intelligence: OFF (ranked by severity only)."
	}
	s := fmt.Sprintf("Exploit intelligence: CISA KEV %s, EPSS %s", orDash(i.KEVVersion), orDash(i.EPSSDate))
	if i.AliasesUsed > 0 {
		s += fmt.Sprintf(", %d OSV alias(es) resolved", i.AliasesUsed)
	}
	return s + "."
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ID is the primary identifier shown for a finding.
func ID(f model.Finding) string {
	if f.VulnID != "" {
		return f.VulnID
	}
	return f.RuleID
}

// Where is a short location: package@version for vulns, path:line otherwise.
func Where(f model.Finding) string {
	if f.Kind == model.KindVuln && f.Package != nil {
		s := f.Package.Name
		if f.Package.Version != "" {
			s += "@" + f.Package.Version
		}
		return s
	}
	if f.Location != nil && f.Location.Path != "" {
		if f.Location.StartLine > 0 {
			return fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine)
		}
		return f.Location.Path
	}
	return "-"
}

func firstReason(f model.Finding) string {
	if len(f.Reasons) == 0 {
		return "-"
	}
	return f.Reasons[0]
}

func scanners(f model.Finding) string {
	var names []string
	seen := map[string]bool{}
	for _, s := range f.Sources {
		if !seen[s.Scanner] {
			seen[s.Scanner] = true
			names = append(names, s.Scanner)
		}
	}
	return strings.Join(names, ",")
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// truncLeft keeps the end of s. Rule IDs, package coordinates and paths carry
// their most specific part at the end ("...jdbc-sqli", "...@2.14.1").
func truncLeft(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n+1:])
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;").Replace(s)
}

func mdLink(text, url string) string {
	if strings.HasPrefix(url, "https://") {
		return "[" + mdEscape(text) + "](" + strings.ReplaceAll(url, ")", "%29") + ")"
	}
	return mdEscape(text)
}
