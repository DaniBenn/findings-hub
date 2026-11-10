package check

import (
	"context"
	"testing"
	"time"

	"github.com/DaniBenn/findings-hub/internal/model"
	"github.com/DaniBenn/findings-hub/internal/policy"
	"github.com/DaniBenn/findings-hub/internal/report"
)

var fixedNow = func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }

func runWith(t *testing.T, policyYAML string, baseline *policy.Baseline) report.Report {
	t.Helper()
	pol, err := policy.Parse([]byte(policyYAML), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), Options{
		Inputs: allInputs, FailOn: pol.FailOn(), Prioritize: pol.PrioritizeConfig(),
		Policy: pol, Baseline: baseline, Enricher: fixtureEnricher(t), Now: fixedNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestSuppressionUnblocksGate(t *testing.T) {
	rep := runWith(t, `version: 1
suppressions:
  - id: aws-access-key-id
    path: config/*.env
    reason: "Rotated 2026-11-01; key revoked, history rewrite tracked in SEC-42"
    expires: 2026-12-31
`, nil)
	s := rep.Summary
	// Remaining P0: Log4Shell (KEV). The secret is suppressed.
	if s.Suppressed != 1 || s.Blocking != 1 || s.ByPriority["P0"] != 1 {
		t.Errorf("summary = %+v", s)
	}
	if len(rep.Findings) != 8 {
		t.Errorf("suppressed findings must stay in the report (JSON): got %d", len(rep.Findings))
	}
}

func TestExpiredSuppressionWarnsAndBlocks(t *testing.T) {
	rep := runWith(t, `version: 1
suppressions:
  - {id: CVE-2021-44228, reason: "legacy box, isolated", expires: 2026-01-31}
`, nil)
	if rep.Summary.Suppressed != 0 || rep.Summary.Blocking != 2 || len(rep.Summary.Warnings) != 1 {
		t.Errorf("summary = %+v", rep.Summary)
	}
}

func TestBaselineNewOnly(t *testing.T) {
	// Baseline everything from a run, then re-run: nothing should gate.
	first := runWith(t, "version: 1\n", nil)
	b := policy.NewBaseline(first.Findings, "test", fixedNow(), func(f model.Finding) (string, string) {
		return report.ID(f), report.Where(f)
	})
	rep := runWith(t, "version: 1\ngate: {fail_on: [P0, P1]}\n", b)
	s := rep.Summary
	if s.Baselined != 8 || s.Blocking != 0 || s.GateFailed {
		t.Errorf("summary = %+v", s)
	}

	// Simulate a baseline taken before Log4Shell was added to KEV (it was P1
	// then). It is P0 now and P0 gates, so it must escalate back to open.
	entries := append([]policy.BaselineEntry(nil), b.Findings...)
	for i := range entries {
		if entries[i].ID == "CVE-2021-44228" {
			entries[i].Priority = model.P1
		}
	}
	rep = runWith(t, "version: 1\n", &policy.Baseline{SchemaVersion: 1, Findings: entries})
	if rep.Summary.Escalated != 1 || rep.Summary.Blocking != 1 || rep.Summary.Baselined != 7 {
		t.Errorf("escalation: summary = %+v", rep.Summary)
	}
}
