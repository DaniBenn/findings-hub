package prioritize

import (
	"strings"
	"testing"

	"github.com/DaniBenn/findings-hub/internal/model"
)

func TestAssess(t *testing.T) {
	cfg := DefaultConfig()
	pkg := func(scope, fix string) *model.Package {
		return &model.Package{Name: "p", Version: "1", Scope: scope, FixedVersion: fix}
	}
	tests := []struct {
		name       string
		f          model.Finding
		want       model.Priority
		wantReason string
	}{
		{"secret always P0", model.Finding{Kind: model.KindSecret, RuleID: "aws", Severity: model.SeverityLow}, model.P0, "secret"},
		{"KEV beats low severity", model.Finding{Kind: model.KindVuln, Severity: model.SeverityLow, KEV: &model.KEV{DateAdded: "2021-12-10"}, Package: pkg("", "2")}, model.P0, "CISA KEV"},
		{"high EPSS + high sev", model.Finding{Kind: model.KindVuln, Severity: model.SeverityHigh, EPSS: &model.EPSS{Score: 0.6}, Package: pkg("", "")}, model.P0, "EPSS 60%"},
		{"high EPSS + medium sev", model.Finding{Kind: model.KindVuln, Severity: model.SeverityMedium, EPSS: &model.EPSS{Score: 0.6}, Package: pkg("", "")}, model.P1, "EPSS"},
		{"critical, no intel", model.Finding{Kind: model.KindVuln, Severity: model.SeverityCritical, Package: pkg("", "")}, model.P1, "critical"},
		{"critical but EPSS tiny", model.Finding{Kind: model.KindVuln, Severity: model.SeverityCritical, EPSS: &model.EPSS{Score: 0.001}, Package: pkg("", "")}, model.P1, "critical"},
		{"high", model.Finding{Kind: model.KindCode, Severity: model.SeverityHigh}, model.P2, "high"},
		{"medium", model.Finding{Kind: model.KindCode, Severity: model.SeverityMedium}, model.P3, "medium"},
		{"unknown", model.Finding{Kind: model.KindCode}, model.P3, "unknown"},
		{"low", model.Finding{Kind: model.KindCode, Severity: model.SeverityLow}, model.P4, "low"},
		{"dev dep lowered", model.Finding{Kind: model.KindVuln, Severity: model.SeverityHigh, Package: pkg("dev", "")}, model.P3, "dev-only"},
		{"dev dep in KEV not lowered", model.Finding{Kind: model.KindVuln, Severity: model.SeverityHigh, KEV: &model.KEV{}, Package: pkg("dev", "")}, model.P0, "KEV"},
		{"P4 stays P4", model.Finding{Kind: model.KindVuln, Severity: model.SeverityLow, Package: pkg("dev", "")}, model.P4, "low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reasons := Assess(tt.f, cfg)
			if got != tt.want {
				t.Errorf("priority = %v, want %v (reasons %v)", got, tt.want, reasons)
			}
			if !strings.Contains(strings.Join(reasons, " | "), tt.wantReason) {
				t.Errorf("reasons %v missing %q", reasons, tt.wantReason)
			}
		})
	}
}

func TestFixReason(t *testing.T) {
	_, r := Assess(model.Finding{Kind: model.KindVuln, Severity: model.SeverityHigh, Package: &model.Package{FixedVersion: "4.17.21"}}, DefaultConfig())
	if !strings.Contains(strings.Join(r, " "), "upgrade to 4.17.21") {
		t.Errorf("reasons = %v", r)
	}
}

func TestSort(t *testing.T) {
	fs := []model.Finding{
		{VulnID: "b", Priority: model.P2, Severity: model.SeverityHigh},
		{VulnID: "a", Priority: model.P0, Severity: model.SeverityLow},
		{VulnID: "c", Priority: model.P2, Severity: model.SeverityCritical},
	}
	Sort(fs)
	if fs[0].VulnID != "a" || fs[1].VulnID != "c" || fs[2].VulnID != "b" {
		t.Errorf("order = %s %s %s", fs[0].VulnID, fs[1].VulnID, fs[2].VulnID)
	}
}
