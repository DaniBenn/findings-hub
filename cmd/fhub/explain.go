package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DaniBenn/findings-hub/internal/check"
	"github.com/DaniBenn/findings-hub/internal/enrich"
	"github.com/DaniBenn/findings-hub/internal/model"
	"github.com/DaniBenn/findings-hub/internal/policy"
	"github.com/DaniBenn/findings-hub/internal/prioritize"
	"github.com/DaniBenn/findings-hub/internal/report"
)

func newExplainCmd(g *globalFlags) *cobra.Command {
	var noEnrich bool
	cmd := &cobra.Command{
		Use:   "explain <id|fingerprint> [scanner-output...]",
		Short: "Show why a finding got its priority, with all sources and exploit data",
		Long: `Runs the same pipeline as "check" and prints the full reasoning for every
finding matching the given CVE/GHSA/alias, scanner rule ID or fingerprint.

Without scanner files, looks up a CVE in the cached exploit intelligence
(CISA KEV and EPSS) only.`,
		Example: `  fhub explain CVE-2021-44228 trivy.json grype.json
  fhub explain 1154734f62f95298 trivy.json
  fhub explain CVE-2024-3094`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, inputs := args[0], args[1:]
			pol, err := policy.Load(g.policyPath, time.Now())
			if err != nil {
				return err
			}
			var findings []model.Finding
			if len(inputs) == 0 {
				if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
					return fmt.Errorf("without scanner files only CVE lookups are possible; pass the scanner output to explain %q", id)
				}
				e, err := g.openEnricher(cmd)
				if err != nil {
					return err
				}
				f := model.Finding{Kind: model.KindVuln, VulnID: strings.ToUpper(id), Title: "(intelligence lookup only)"}
				fs := []model.Finding{f}
				if err := e.Apply(fs); err != nil {
					return err
				}
				fs[0].Priority, fs[0].Reasons = prioritize.Assess(fs[0], pol.PrioritizeConfig())
				fs[0].Reasons = append(fs[0].Reasons, "severity unknown without scanner data: pass scanner output for the full picture")
				findings = fs
			} else {
				opts, err := g.checkOptions(cmd, inputs, pol, noEnrich)
				if err != nil {
					return err
				}
				rep, err := check.Run(cmd.Context(), opts)
				if err != nil {
					return err
				}
				for _, f := range rep.Findings {
					if matchesExplain(id, f) {
						findings = append(findings, f)
					}
				}
				if len(findings) == 0 {
					return fmt.Errorf("no finding matches %q in %d unique finding(s)", id, len(rep.Findings))
				}
			}
			for _, f := range findings {
				report.Explain(cmd.OutOrStdout(), f)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&noEnrich, "no-enrich", false, "skip exploit intelligence")
	return cmd
}

func matchesExplain(id string, f model.Finding) bool {
	if strings.EqualFold(id, f.Fingerprint) || strings.EqualFold(id, f.VulnID) || strings.EqualFold(id, f.RuleID) {
		return true
	}
	for _, a := range f.Aliases {
		if strings.EqualFold(id, a) {
			return true
		}
	}
	return false
}

// openEnricher opens exploit intelligence with the global flags.
func (g *globalFlags) openEnricher(cmd *cobra.Command) (*enrich.Enricher, error) {
	eo, err := g.enrichOptions(cmd)
	if err != nil {
		return nil, err
	}
	return enrich.Open(cmd.Context(), eo)
}
