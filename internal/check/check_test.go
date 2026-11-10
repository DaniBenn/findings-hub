package check

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/DaniBenn/findings-hub/internal/model"
	"github.com/DaniBenn/findings-hub/internal/prioritize"
	"github.com/DaniBenn/findings-hub/internal/report"
)

var allInputs = []string{
	"../../testdata/trivy-fs.json",
	"../../testdata/grype-dir.json",
	"../../testdata/semgrep.sarif",
	"../../testdata/gitleaks.sarif",
}

func TestEndToEnd(t *testing.T) {
	rep, err := Run(context.Background(), Options{Inputs: allInputs, FailOn: []model.Priority{model.P0}, Prioritize: prioritize.DefaultConfig()})
	if err != nil {
		t.Fatal(err)
	}
	s := rep.Summary
	// 11 raw: trivy 5, grype 3, semgrep 2, gitleaks 1.
	// Merges: lodash CVE-2021-23337 (trivy+grype), log4j CVE-2021-44228
	// (trivy+grype), and the AWS key in config/settings.env:3 (trivy+gitleaks)
	// -> 8 unique.
	if s.Raw != 11 || s.Unique != 8 || s.Merged != 3 {
		t.Errorf("raw/unique/merged = %d/%d/%d, want 11/8/3", s.Raw, s.Unique, s.Merged)
	}
	want := map[string]int{"P0": 1, "P1": 1, "P2": 3, "P3": 2, "P4": 1}
	for p, n := range want {
		if s.ByPriority[p] != n {
			t.Errorf("%s = %d, want %d (all: %v)", p, s.ByPriority[p], n, s.ByPriority)
		}
	}
	if !s.GateFailed || s.Blocking != 1 {
		t.Errorf("gate failed=%v blocking=%d, want true/1 (the AWS key)", s.GateFailed, s.Blocking)
	}
	if rep.Findings[0].Priority != model.P0 {
		t.Errorf("findings not sorted by priority")
	}
}

func TestGateDisabled(t *testing.T) {
	rep, err := Run(context.Background(), Options{Inputs: allInputs, Prioritize: prioritize.DefaultConfig()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.GateFailed {
		t.Error("empty fail-on must never fail the gate")
	}
}

func TestReportsRender(t *testing.T) {
	rep, err := Run(context.Background(), Options{Inputs: allInputs, FailOn: []model.Priority{model.P0}, Prioritize: prioritize.DefaultConfig()})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range report.Formats {
		var buf bytes.Buffer
		if err := report.Write(&buf, rep, format); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		out := buf.String()
		if !strings.Contains(out, "CVE-2021-44228") {
			t.Errorf("%s output missing log4j finding", format)
		}
		if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("%s output leaked a secret", format)
		}
	}
}

func TestMissingFile(t *testing.T) {
	if _, err := Run(context.Background(), Options{Inputs: []string{"does-not-exist.json"}}); err == nil {
		t.Fatal("expected error")
	}
}
