package policy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DaniBenn/findings-hub/internal/model"
)

var now = time.Date(2026, 11, 10, 15, 0, 0, 0, time.UTC)

func mustParse(t *testing.T, y string) *Policy {
	t.Helper()
	p, err := Parse([]byte(y), now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestTemplateIsValid(t *testing.T) {
	p := mustParse(t, Template(now))
	if got := p.FailOn(); len(got) != 1 || got[0] != model.P0 {
		t.Errorf("fail_on = %v", got)
	}
	// The commented examples must be valid too once uncommented.
	lines := strings.Split(strings.Replace(Template(now), "suppressions: []", "suppressions:", 1), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "#  ") {
			lines[i] = l[1:]
		}
	}
	p = mustParse(t, strings.Join(lines, "\n"))
	if len(p.Suppressions) != 2 {
		t.Errorf("example suppressions = %d, want 2", len(p.Suppressions))
	}
}

func TestDefaultsWhenEmpty(t *testing.T) {
	p := mustParse(t, "version: 1\n")
	if len(p.FailOn()) != 1 || p.Gate.Baseline != DefaultBaselineFile {
		t.Errorf("defaults not applied: %+v", p.Gate)
	}
	c := p.PrioritizeConfig()
	if c.EPSSP0 != 0.4 || c.EPSSP1 != 0.1 || !c.DowngradeDev {
		t.Errorf("prioritize defaults = %+v", c)
	}
}

func TestOverrides(t *testing.T) {
	p := mustParse(t, "version: 1\ngate: {fail_on: [P0, P1]}\nprioritize: {epss_p0: 0.2, downgrade_dev: false}\n")
	c := p.PrioritizeConfig()
	if c.EPSSP0 != 0.2 || c.EPSSP1 != 0.1 || c.DowngradeDev {
		t.Errorf("config = %+v", c)
	}
	if len(p.FailOn()) != 2 {
		t.Errorf("fail_on = %v", p.FailOn())
	}
}

func TestValidationErrors(t *testing.T) {
	tests := map[string]string{
		"unknown key (typo)":   "version: 1\nsuppresions: []\n",
		"bad version":          "version: 2\n",
		"bad priority":         "version: 1\ngate: {fail_on: [P9]}\n",
		"epss out of range":    "version: 1\nprioritize: {epss_p0: 4}\n",
		"no matcher":           "version: 1\nsuppressions: [{reason: x, expires: 2027-01-01}]\n",
		"no reason":            "version: 1\nsuppressions: [{id: CVE-1, expires: 2027-01-01}]\n",
		"no expiry":            "version: 1\nsuppressions: [{id: CVE-1, reason: x}]\n",
		"bad date":             "version: 1\nsuppressions: [{id: CVE-1, reason: x, expires: 01/02/2027}]\n",
		"too far out":          "version: 1\nsuppressions: [{id: CVE-1, reason: x, expires: 2028-06-01}]\n",
		"bad vex status":       "version: 1\nsuppressions: [{id: CVE-1, reason: x, expires: 2027-01-01, vex: {status: nope}}]\n",
		"not_affected no just": "version: 1\nsuppressions: [{id: CVE-1, reason: x, expires: 2027-01-01, vex: {status: not_affected}}]\n",
	}
	for name, y := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(y), now); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestLoadMissingDefaultFileIsFine(t *testing.T) {
	t.Chdir(t.TempDir())
	p, err := Load("", now)
	if err != nil || p.Source != "" {
		t.Fatalf("p=%+v err=%v", p, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), now); err == nil {
		t.Fatal("an explicitly given missing policy must be an error")
	}
}

func lodash() model.Finding {
	return model.Finding{
		Kind: model.KindVuln, Fingerprint: "fp-lodash", VulnID: "CVE-2021-23337", Aliases: []string{"GHSA-35jh-r3h4-6jhm"},
		Package:  &model.Package{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20?x=y"},
		Location: &model.Location{Path: "package-lock.json"}, Priority: model.P1, Status: model.StatusOpen,
	}
}

func secret(path string) model.Finding {
	return model.Finding{Kind: model.KindSecret, Fingerprint: "fp-" + path, RuleID: "generic-api-key",
		Location: &model.Location{Path: path, StartLine: 1}, Priority: model.P0, Status: model.StatusOpen}
}

func TestSuppressionMatching(t *testing.T) {
	tests := []struct {
		name string
		rule string
		f    model.Finding
		want bool
	}{
		{"by CVE", "id: CVE-2021-23337", lodash(), true},
		{"by alias, case-insensitive", "id: ghsa-35jh-r3h4-6jhm", lodash(), true},
		{"by fingerprint", "fingerprint: fp-lodash", lodash(), true},
		{"id + package any version", "id: CVE-2021-23337\n    package: pkg:npm/lodash", lodash(), true},
		{"id + exact version", "id: CVE-2021-23337\n    package: pkg:npm/lodash@4.17.20", lodash(), true},
		{"id + other version", "id: CVE-2021-23337\n    package: pkg:npm/lodash@4.17.21", lodash(), false},
		{"package by name", "id: CVE-2021-23337\n    package: lodash", lodash(), true},
		{"other package", "id: CVE-2021-23337\n    package: pkg:npm/underscore", lodash(), false},
		{"rule + glob", `id: generic-api-key` + "\n    path: \"test/**\"", secret("test/fixtures/a/keys.env"), true},
		{"glob does not match prod", `id: generic-api-key` + "\n    path: \"test/**\"", secret("src/config.env"), false},
		{"single star stays in segment", `path: "test/*.env"`, secret("test/deep/x.env"), false},
		{"**/ matches zero dirs", `path: "**/keys.env"`, secret("keys.env"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustParse(t, "version: 1\nsuppressions:\n  - "+tt.rule+"\n    reason: test\n    expires: 2027-01-01\n")
			fs := []model.Finding{tt.f}
			p.ApplySuppressions(fs, now)
			if got := fs[0].Status == model.StatusSuppressed; got != tt.want {
				t.Errorf("suppressed = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpiredSuppressionReactivates(t *testing.T) {
	p := mustParse(t, "version: 1\nsuppressions:\n  - {id: CVE-2021-23337, reason: old decision, expires: 2026-11-09}\n")
	fs := []model.Finding{lodash()}
	res := p.ApplySuppressions(fs, now)
	if fs[0].Status != model.StatusOpen || len(res.Expired) != 1 {
		t.Fatalf("status=%s res=%+v", fs[0].Status, res)
	}
	if !strings.Contains(strings.Join(fs[0].Reasons, " "), "suppression expired on 2026-11-09") {
		t.Errorf("reasons = %v", fs[0].Reasons)
	}
	// Expiry is inclusive: valid through the whole expiry day.
	p = mustParse(t, "version: 1\nsuppressions:\n  - {id: CVE-2021-23337, reason: x, expires: 2026-11-10}\n")
	fs = []model.Finding{lodash()}
	res = p.ApplySuppressions(fs, now)
	if fs[0].Status != model.StatusSuppressed || len(res.ExpiringSoon) != 1 {
		t.Errorf("same-day expiry should still apply and warn: %s %+v", fs[0].Status, res)
	}
}

func TestUnusedSuppressionReported(t *testing.T) {
	p := mustParse(t, "version: 1\nsuppressions:\n  - {id: CVE-2000-0001, reason: gone, expires: 2027-01-01}\n")
	res := p.ApplySuppressions([]model.Finding{lodash()}, now)
	if len(res.Unused) != 1 {
		t.Errorf("unused = %v", res.Unused)
	}
}

func TestSuppressionCarriesVEX(t *testing.T) {
	p := mustParse(t, "version: 1\nsuppressions:\n  - id: CVE-2021-23337\n    reason: unreachable\n    expires: 2027-01-01\n    vex: {status: not_affected, justification: vulnerable_code_not_in_execute_path}\n")
	fs := []model.Finding{lodash()}
	p.ApplySuppressions(fs, now)
	s := fs[0].Suppression
	if s == nil || s.VEXStatus != "not_affected" || s.VEXJustification != "vulnerable_code_not_in_execute_path" || s.Reason != "unreachable" {
		t.Errorf("suppression = %+v", s)
	}
}

func TestBaselineRoundTripAndEscalation(t *testing.T) {
	describe := func(f model.Finding) (string, string) { return f.VulnID, "" }
	old := lodash()
	old.Priority = model.P2
	b := NewBaseline([]model.Finding{old, secret("a.env")}, "test", now, describe)
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := b.Write(path); err != nil {
		t.Fatal(err)
	}
	b2, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b2.Findings) != 2 {
		t.Fatalf("entries = %d", len(b2.Findings))
	}

	failOn := []model.Priority{model.P0, model.P1}
	same := secret("a.env")    // P0 then, P0 now -> baselined
	escalated := lodash()      // P2 then, P1 now (e.g. EPSS jumped) and P1 gates -> open
	fresh := secret("new.env") // not in baseline -> open
	fs := []model.Finding{same, escalated, fresh}
	res := b2.Apply(fs, failOn)
	if fs[0].Status != model.StatusBaselined {
		t.Errorf("unchanged finding should be baselined, got %s", fs[0].Status)
	}
	if fs[1].Status != model.StatusOpen || res.Escalated != 1 || !strings.Contains(fs[1].Reasons[0], "was P2") {
		t.Errorf("escalated finding: status=%s reasons=%v res=%+v", fs[1].Status, fs[1].Reasons, res)
	}
	if fs[2].Status != model.StatusOpen {
		t.Errorf("new finding should be open")
	}

	// Escalation that does NOT reach a gating priority stays baselined.
	less := lodash()
	less.Priority = model.P1
	res = b2.Apply([]model.Finding{less}, []model.Priority{model.P0})
	if res.Baselined != 1 {
		t.Errorf("non-gating escalation should stay baselined: %+v", res)
	}
}

func TestBaselineExcludesSuppressed(t *testing.T) {
	s := lodash()
	s.Status = model.StatusSuppressed
	b := NewBaseline([]model.Finding{s}, "t", now, func(model.Finding) (string, string) { return "", "" })
	if len(b.Findings) != 0 {
		t.Error("suppressed findings must not be baselined (their expiry would be bypassed)")
	}
}

func TestMissingBaselineHelpfulError(t *testing.T) {
	_, err := LoadBaseline(filepath.Join(t.TempDir(), "x.json"))
	if err == nil || !strings.Contains(err.Error(), "fhub baseline create") {
		t.Fatalf("err = %v", err)
	}
}
