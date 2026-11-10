// Package check runs the full pipeline:
// ingest -> OSV aliases -> dedupe -> KEV/EPSS -> prioritize -> gate.
// It is kept separate from the CLI so it can be tested and reused (Action,
// server) without cobra.
package check

import (
	"context"
	"fmt"
	"slices"

	"github.com/DaniBenn/findings-hub/internal/dedupe"
	"github.com/DaniBenn/findings-hub/internal/enrich"
	"github.com/DaniBenn/findings-hub/internal/ingest"
	"github.com/DaniBenn/findings-hub/internal/model"
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

	sum := report.Summary{
		Inputs:     inputs,
		Raw:        rawCount,
		Unique:     len(fs),
		Merged:     rawCount - len(fs),
		ByPriority: map[string]int{"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0},
		GateFailOn: []string{},
		Intel:      intel,
	}
	for _, p := range opts.FailOn {
		sum.GateFailOn = append(sum.GateFailOn, p.String())
	}
	for _, f := range fs {
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
