package dedupe

import (
	"slices"
	"testing"

	"github.com/DaniBenn/findings-hub/internal/model"
)

func vuln(scanner, id string, aliases []string, purl string, sev model.Severity) model.Finding {
	return model.Finding{
		Kind: model.KindVuln, Title: id, VulnID: id, Aliases: aliases, Severity: sev,
		Package: &model.Package{Name: "lodash", Version: "4.17.20", PURL: purl},
		Sources: []model.Source{{Scanner: scanner, RuleID: id}},
	}
}

func TestMergeAcrossScannersViaAliases(t *testing.T) {
	in := []model.Finding{
		vuln("trivy", "CVE-2021-23337", nil, "pkg:npm/lodash@4.17.20", model.SeverityHigh),
		vuln("grype", "GHSA-35jh-r3h4-6jhm", []string{"CVE-2021-23337"}, "pkg:npm/lodash@4.17.20?foo=bar", model.SeverityMedium),
		vuln("grype", "CVE-2020-28500", nil, "pkg:npm/lodash@4.17.20", model.SeverityMedium),
	}
	out := Merge(in)
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(out), out)
	}
	m := out[0]
	if m.VulnID != "CVE-2021-23337" {
		t.Errorf("canonical = %q, want the CVE", m.VulnID)
	}
	if !slices.Equal(m.Aliases, []string{"GHSA-35jh-r3h4-6jhm"}) {
		t.Errorf("aliases = %v", m.Aliases)
	}
	if len(m.Sources) != 2 {
		t.Errorf("sources = %+v, want trivy+grype", m.Sources)
	}
	if m.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want max (high)", m.Severity)
	}
}

func TestTransitiveAliasMerge(t *testing.T) {
	// A~B via shared alias, B~C via another: all three are one vuln.
	p := "pkg:npm/x@1"
	in := []model.Finding{
		vuln("s1", "GHSA-aaaa-aaaa-aaaa", nil, p, model.SeverityLow),
		vuln("s3", "OSV-1", []string{"CVE-2020-0001"}, p, model.SeverityLow),
		vuln("s2", "CVE-2020-0001", []string{"GHSA-aaaa-aaaa-aaaa"}, p, model.SeverityLow),
	}
	if out := Merge(in); len(out) != 1 {
		t.Fatalf("got %d, want 1", len(out))
	}
}

func TestDifferentVersionsNotMerged(t *testing.T) {
	in := []model.Finding{
		vuln("trivy", "CVE-2021-23337", nil, "pkg:npm/lodash@4.17.20", model.SeverityHigh),
		vuln("trivy", "CVE-2021-23337", nil, "pkg:npm/lodash@4.17.19", model.SeverityHigh),
	}
	if out := Merge(in); len(out) != 2 {
		t.Fatalf("got %d, want 2", len(out))
	}
}

func TestFingerprintStableAcrossInputOrder(t *testing.T) {
	a := vuln("trivy", "CVE-2021-23337", nil, "pkg:npm/lodash@4.17.20", model.SeverityHigh)
	b := vuln("grype", "GHSA-35jh-r3h4-6jhm", []string{"CVE-2021-23337"}, "pkg:npm/lodash@4.17.20", model.SeverityHigh)
	x := Merge([]model.Finding{a, b})
	y := Merge([]model.Finding{b, a})
	if x[0].Fingerprint != y[0].Fingerprint {
		t.Fatalf("fingerprint depends on order: %s vs %s", x[0].Fingerprint, y[0].Fingerprint)
	}
}

func TestCodeFindingSurvivesLineMove(t *testing.T) {
	mk := func(line int) model.Finding {
		return model.Finding{
			Kind: model.KindCode, RuleID: "sqli",
			Location:  &model.Location{Path: "a.java", StartLine: line},
			MatchHash: model.HashContent(`stmt.executeQuery("..." + id)`),
		}
	}
	if fingerprint(mk(10)) != fingerprint(mk(55)) {
		t.Fatal("same code on a different line should keep its fingerprint")
	}
	other := mk(10)
	other.MatchHash = model.HashContent("something else")
	if fingerprint(mk(10)) == fingerprint(other) {
		t.Fatal("different code should get a different fingerprint")
	}
}

func TestSameSecretFromDifferentScannersMerged(t *testing.T) {
	mk := func(scanner, rule, match string, sev model.Severity) model.Finding {
		return model.Finding{
			Kind: model.KindSecret, RuleID: rule, Severity: sev,
			Location:  &model.Location{Path: "config/settings.env", StartLine: 3},
			MatchHash: model.HashContent(match),
			Sources:   []model.Source{{Scanner: scanner, RuleID: rule}},
		}
	}
	out := Merge([]model.Finding{
		mk("trivy", "aws-access-key-id", "AWS_ACCESS_KEY_ID=****", model.SeverityCritical),
		mk("gitleaks", "aws-access-token", "AKIA...", model.SeverityMedium),
	})
	if len(out) != 1 || len(out[0].Sources) != 2 || out[0].Severity != model.SeverityCritical {
		t.Fatalf("got %+v", out)
	}
}

func TestDuplicateCodeFindingsMerged(t *testing.T) {
	f := model.Finding{
		Kind: model.KindCode, RuleID: "r1", Location: &model.Location{Path: "a.go", StartLine: 3},
		Sources: []model.Source{{Scanner: "semgrep", RuleID: "r1", File: "run1.sarif"}},
	}
	g := f
	g.Sources = []model.Source{{Scanner: "semgrep", RuleID: "r1", File: "run2.sarif"}}
	out := Merge([]model.Finding{f, g})
	if len(out) != 1 || len(out[0].Sources) != 2 {
		t.Fatalf("got %+v", out)
	}
}
