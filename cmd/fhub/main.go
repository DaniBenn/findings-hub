// Command fhub ingests security scanner output, deduplicates and prioritizes
// it by real-world exploitability, and gates CI on policy.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DaniBenn/findings-hub/internal/check"
	"github.com/DaniBenn/findings-hub/internal/model"
	"github.com/DaniBenn/findings-hub/internal/prioritize"
	"github.com/DaniBenn/findings-hub/internal/report"
)

// Set at build time: -ldflags "-X main.version=v0.1.0"
var version = "dev"

// Exit codes are part of the CI contract.
const (
	exitOK         = 0
	exitGateFailed = 1
	exitError      = 2
)

// errGateFailed signals a policy failure (not a tool error).
var errGateFailed = errors.New("security gate failed")

func main() {
	err := newRootCmd().Execute()
	switch {
	case err == nil:
		os.Exit(exitOK)
	case errors.Is(err, errGateFailed):
		os.Exit(exitGateFailed)
	default:
		fmt.Fprintln(os.Stderr, "fhub: error:", err)
		os.Exit(exitError)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "fhub",
		Short:         "Turn every security scanner's output into the few findings that matter",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newCheckCmd())
	return root
}

func newCheckCmd() *cobra.Command {
	var (
		format string
		failOn string
		output string
	)
	cmd := &cobra.Command{
		Use:   "check [flags] <scanner-output>...",
		Short: "Ingest, deduplicate, prioritize and gate scanner results",
		Long: `Reads one or more scanner result files (SARIF 2.1.0, Trivy JSON, Grype JSON),
merges duplicates across scanners, assigns each finding a priority P0..P4
with reasons, and exits non-zero if any finding hits the --fail-on gate.

Exit codes: 0 = passed, 1 = gate failed, 2 = error.
Use "-" to read a single input from stdin.`,
		Example: `  trivy fs --format json -o trivy.json .
  grype dir:. -o json > grype.json
  semgrep scan --sarif -o semgrep.sarif
  fhub check trivy.json grype.json semgrep.sarif --fail-on P0,P1`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gate, err := parsePriorities(failOn)
			if err != nil {
				return err
			}
			rep, err := check.Run(check.Options{
				Inputs:     args,
				FailOn:     gate,
				Prioritize: prioritize.DefaultConfig(),
				Tool:       report.Tool{Name: "fhub", Version: version},
			})
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if output != "" && output != "-" {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			if err := report.Write(w, rep, format); err != nil {
				return err
			}
			if rep.Summary.GateFailed {
				fmt.Fprintf(cmd.ErrOrStderr(), "fhub: security gate FAILED: %d finding(s) at %s\n",
					rep.Summary.Blocking, strings.Join(rep.Summary.GateFailOn, ","))
				return errGateFailed
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: "+strings.Join(report.Formats, ", "))
	cmd.Flags().StringVar(&failOn, "fail-on", "P0", `comma-separated priorities that fail the gate ("" disables the gate)`)
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the report to a file instead of stdout")
	return cmd
}

func parsePriorities(s string) ([]model.Priority, error) {
	var out []model.Priority
	for _, part := range strings.Split(s, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		p, err := model.ParsePriority(part)
		if err != nil {
			return nil, fmt.Errorf("--fail-on: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}
