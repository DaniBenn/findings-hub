package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DaniBenn/findings-hub/internal/model"
)

func TestExplain(t *testing.T) {
	f := model.Finding{
		Kind: model.KindVuln, VulnID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Title: "Log4Shell",
		Severity: model.SeverityCritical, CVSS: 10, Priority: model.P0, Status: model.StatusSuppressed,
		Package:     &model.Package{Name: "log4j-core", Version: "2.14.1", FixedVersion: "2.15.0"},
		KEV:         &model.KEV{DateAdded: "2021-12-10", Ransomware: true},
		EPSS:        &model.EPSS{Score: 0.97512, Percentile: 0.9999, Date: "2026-11-09"},
		Reasons:     []string{"in CISA KEV"},
		Suppression: &model.Suppression{Reason: "isolated host", Expires: "2026-12-01", VEXStatus: "not_affected", VEXJustification: "inline_mitigations_already_exist"},
		Sources:     []model.Source{{Scanner: "trivy", RuleID: "CVE-2021-44228", Severity: "CRITICAL", File: "t.json"}},
		Fingerprint: "abc123",
	}
	var buf bytes.Buffer
	Explain(&buf, f)
	out := buf.String()
	for _, want := range []string{
		"P0 (suppressed)  CVE-2021-44228", "CVSS 10.0", "log4j-core@2.14.1", "Fixed in:     2.15.0",
		"in CISA KEV (added 2021-12-10", "known ransomware use", "97.512% chance", "percentile 1.000",
		"suppressed until 2026-12-01: isolated host", "VEX: not_affected / inline_mitigations_already_exist",
		"trivy: rule CVE-2021-44228", "abc123",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("explain output missing %q:\n%s", want, out)
		}
	}
}

func TestExplainNonVuln(t *testing.T) {
	var buf bytes.Buffer
	Explain(&buf, model.Finding{Kind: model.KindSecret, RuleID: "aws", Priority: model.P0, Status: model.StatusOpen})
	if !strings.Contains(buf.String(), "n/a (not a dependency vulnerability)") || !strings.Contains(buf.String(), "intelligence lookup only") {
		t.Errorf("output:\n%s", buf.String())
	}
}
