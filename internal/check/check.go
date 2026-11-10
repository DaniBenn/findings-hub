// Package check runs the full pipeline:
// ingest -> OSV aliases -> dedupe -> KEV/EPSS -> prioritize -> gate.
// It is kept separate from the CLI so it can be tested and reused (Action,
// server) without cobra.
package check

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/DaniBenn/findings-hub/internal/dedupe"
	"github.com/DaniBenn/findings-hub/internal/enrich"
	"github.com/DaniBenn/findings-hub/internal/ingest"
	"github.com/DaniBenn/findings-hub/internal/model"
	"github.com/DaniBenn/findings-hub/internal/policy"
	"github.com/DaniBenn/findings-hub/internal/prioritize"
	"github.com/DaniBenn/findings-hub/internal/report"
)

// Options configures a run.
type Options struct {
	Inputs     []string
	FailOn     []model.Priority
	Prioritize prioritize.Config
	Tool       report.Tool
	// Enricher adds exploit intelligence. nil = rank by severity only.
	Enricher *enrich.Enricher
	// Policy supplies suppressions. nil = no suppressions.
	Policy *policy.Policy
	// Baseline, when set, marks pre-existing findings so only new (or
	// escalated) ones fail the gate.
	Baseline *policy.Baseline
	// Now is injectable for tests. nil = time.Now.
	Now func() time.Time
}

// Run executes the pipeline and returns the report. A failed gate is not an
// error: inspect Report.Summary.GateFailed.
func Run(ctx context.Context, opts Options) (report.Report, error) {
	if len(opts.Inputs) == 0 {
		return report.Report{}, fmt.Errorf("no input files given")
	}
	var raw []model.Finding
	for _, in := range opts.Inputs {
		res, err := ingest.File(in)
		if err != nil {
			return report.Report{}, err
		}
		raw = append(raw, res.Findings...)
	}
	return Evaluate(ctx, raw, len(opts.Inputs), opts)
}

// Evaluate runs everything after ingestion.
func Evaluate(ctx context.Context, raw []model.Finding, inputs int, opts Options) (report.Report, error) {
	rawCount := len(raw)
	if opts.Enricher != nil {
		// Aliases first: they decide canonical IDs and thus fingerprints.
		opts.Enricher.AddAliases(ctx, raw)
	}
	fs := dedupe.Merge(raw)
	intel := enrich.Info{}
	if opts.Enricher != nil {
		if err := opts.Enricher.Apply(fs); err != nil {
			return report.Report{}, err
		}
		intel = opts.Enricher.Info()
	}
	prioritize.Apply(fs, opts.Prioritize)
	prioritize.Sort(fs)

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	for i := range fs {
		fs[i].Status = model.StatusOpen
	}
	sum := report.Summary{
		Inputs:     inputs,
		Raw:        rawCount,
		Unique:     len(fs),
		Merged:     rawCount - len(fs),
		ByPriority: map[string]int{"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0},
		GateFailOn: []string{},
		Intel:      intel,
		Warnings:   []string{},
	}
	if opts.Policy != nil {
		sr := opts.Policy.ApplySuppressions(fs, now())
		sum.Suppressed = sr.Suppressed
		for _, s := range sr.Expired {
			sum.Warnings = append(sum.Warnings, s+": the finding is active again")
		}
		for _, s := range sr.ExpiringSoon {
			sum.Warnings = append(sum.Warnings, s)
		}
		for _, s := range sr.Unused {
			sum.Warnings = append(sum.Warnings, s+" matched nothing: remove it if the issue is gone")
		}
	}
	if opts.Baseline != nil {
		br := opts.Baseline.Apply(fs, opts.FailOn)
		sum.Baselined, sum.Escalated = br.Baselined, br.Escalated
	}

	for _, p := range opts.FailOn {
		sum.GateFailOn = append(sum.GateFailOn, p.String())
	}
	for _, f := range fs {
		if f.Status != model.StatusOpen {
			continue
		}
		sum.ByPriority[f.Priority.String()]++
		if slices.Contains(opts.FailOn, f.Priority) {
			sum.Blocking++
		}
	}
	sum.GateFailed = sum.Blocking > 0
	if fs == nil {
		fs = []model.Finding{}
	}
	return report.Report{SchemaVersion: report.SchemaVersion, Tool: opts.Tool, Summary: sum, Findings: fs}, nil
}
