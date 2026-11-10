// Command fhub ingests security scanner output, deduplicates and prioritizes
// it by real-world exploitability, and gates CI on policy.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/DaniBenn/findings-hub/internal/check"
	"github.com/DaniBenn/findings-hub/internal/enrich"
	"github.com/DaniBenn/findings-hub/internal/model"
	"github.com/DaniBenn/findings-hub/internal/policy"
	"github.com/DaniBenn/findings-hub/internal/report"
)

// Set at build time: -ldflags "-X main.version=v0.1.0"
var version = "dev"

func init() {
	// `go install ...@v0.1.0` builds carry the module version but no ldflags.
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = strings.TrimPrefix(bi.Main.Version, "v")
		}
	}
}

// Exit codes are part of the CI contract.
const (
	exitOK         = 0
	exitGateFailed = 1
	exitError      = 2
)

// errGateFailed signals a policy failure (not a tool error).
var errGateFailed = errors.New("security gate failed")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := newRootCmd().ExecuteContext(ctx)
	stop()
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

// globalFlags are shared by every command.
type globalFlags struct {
	cacheDir   string
	offline    bool
	policyPath string
}

func (g *globalFlags) enrichOptions(cmd *cobra.Command) (enrich.Options, error) {
	dir := g.cacheDir
	if dir == "" {
		var err error
		if dir, err = enrich.DefaultCacheDir(); err != nil {
			return enrich.Options{}, err
		}
	}
	return enrich.Options{
		CacheDir: dir,
		Offline:  g.offline,
		Fetcher:  enrich.NewFetcher(version),
		Warn:     func(msg string) { fmt.Fprintln(cmd.ErrOrStderr(), "fhub: warning:", msg) },
	}, nil
}

func newRootCmd() *cobra.Command {
	g := &globalFlags{}
	root := &cobra.Command{
		Use:           "fhub",
		Short:         "Turn every security scanner's output into the few findings that matter",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&g.cacheDir, "cache-dir", "", "exploit-intelligence cache (default: $FHUB_CACHE_DIR or the OS user cache dir)")
	root.PersistentFlags().BoolVar(&g.offline, "offline", false, "never access the network; use cached data only")
	root.PersistentFlags().StringVar(&g.policyPath, "policy", "", "policy file (default: "+policy.DefaultFile+" if present)")
	root.AddCommand(newCheckCmd(g), newExplainCmd(g), newDBCmd(g), newBaselineCmd(g), newInitCmd())
	return root
}

func newCheckCmd(g *globalFlags) *cobra.Command {
	var (
		format       string
		failOn       string
		output       string
		noEnrich     bool
		newOnly      bool
		showAll      bool
		baselinePath string
		reportJSON   string
		reportMD     string
	)
	cmd := &cobra.Command{
		Use:   "check [flags] <scanner-output>...",
		Short: "Ingest, deduplicate, prioritize and gate scanner results",
		Long: `Reads one or more scanner result files (SARIF 2.1.0, Trivy JSON, Grype JSON),
merges duplicates across scanners, enriches vulnerabilities with CISA KEV,
FIRST EPSS and OSV data, assigns each finding a priority P0..P4 with reasons,
and exits non-zero if any finding hits the --fail-on gate.

Policy (thresholds, gate, expiring suppressions, baseline) is read from
.fhub.yaml when present; create one with "fhub init".

Exploit data is cached and refreshed at most once a day. If no data can be
loaded the command fails rather than silently ranking by severity; pass
--no-enrich to opt out explicitly.

Exit codes: 0 = passed, 1 = gate failed, 2 = error.
Use "-" to read a single input from stdin.`,
		Example: `  trivy fs --format json -o trivy.json .
  grype dir:. -o json > grype.json
  semgrep scan --sarif -o semgrep.sarif
  fhub check trivy.json grype.json semgrep.sarif --fail-on P0,P1`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := policy.Load(g.policyPath, time.Now())
			if err != nil {
				return err
			}
			opts, err := g.checkOptions(cmd, args, pol, noEnrich)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("fail-on") {
				if opts.FailOn, err = parsePriorities(failOn); err != nil {
					return err
				}
			}
			if newOnly || pol.Gate.NewOnly {
				path := pol.Gate.Baseline
				if cmd.Flags().Changed("baseline") {
					path = baselinePath
				}
				if opts.Baseline, err = policy.LoadBaseline(path); err != nil {
					return err
				}
			}
			rep, err := check.Run(cmd.Context(), opts)
			if err != nil {
				return err
			}
			rep.ShowAll = showAll
			for _, warn := range rep.Summary.Warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "fhub: warning:", warn)
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
			for path, extraFormat := range map[string]string{reportJSON: "json", reportMD: "markdown"} {
				if path == "" {
					continue
				}
				if err := writeReportFile(path, rep, extraFormat); err != nil {
					return err
				}
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
	cmd.Flags().StringVar(&failOn, "fail-on", "P0", `comma-separated priorities that fail the gate ("" disables it); overrides gate.fail_on`)
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the report to a file instead of stdout")
	cmd.Flags().BoolVar(&noEnrich, "no-enrich", false, "skip exploit intelligence (KEV/EPSS/OSV) and rank by severity only")
	cmd.Flags().BoolVar(&newOnly, "new-only", false, "only fail on findings not in the baseline (or escalated since); same as gate.new_only")
	cmd.Flags().StringVar(&baselinePath, "baseline", policy.DefaultBaselineFile, "baseline file used with --new-only / gate.new_only")
	cmd.Flags().BoolVar(&showAll, "show-all", false, "also list suppressed and baselined findings")
	cmd.Flags().StringVar(&reportJSON, "report-json", "", "additionally write the full JSON report to this file")
	cmd.Flags().StringVar(&reportMD, "report-markdown", "", "additionally write a Markdown summary (for PR comments / job summaries) to this file")
	return cmd
}

func writeReportFile(path string, rep report.Report, format string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := report.Write(f, rep, format); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// checkOptions builds pipeline options shared by `check` and `baseline create`.
func (g *globalFlags) checkOptions(cmd *cobra.Command, args []string, pol *policy.Policy, noEnrich bool) (check.Options, error) {
	opts := check.Options{
		Inputs:     args,
		FailOn:     pol.FailOn(),
		Prioritize: pol.PrioritizeConfig(),
		Policy:     pol,
		Tool:       report.Tool{Name: "fhub", Version: version},
	}
	if !noEnrich {
		eo, err := g.enrichOptions(cmd)
		if err != nil {
			return opts, err
		}
		if opts.Enricher, err = enrich.Open(cmd.Context(), eo); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

func newBaselineCmd(g *globalFlags) *cobra.Command {
	bl := &cobra.Command{
		Use:   "baseline",
		Short: "Manage the baseline of accepted pre-existing findings",
		Long: `A baseline lets you adopt the gate on an existing codebase: findings in the
baseline do not fail the build when gate.new_only is set (or --new-only is
passed), so the gate only blocks NEW issues while you burn down the old ones.

A baselined finding that escalates into a gating priority (for example
because it was added to CISA KEV) fails the gate again.

Commit the baseline file so changes to it are reviewed in pull requests.`,
	}
	var (
		output   string
		noEnrich bool
	)
	create := &cobra.Command{
		Use:   "create [flags] <scanner-output>...",
		Short: "Snapshot current open findings into a baseline file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := policy.Load(g.policyPath, time.Now())
			if err != nil {
				return err
			}
			opts, err := g.checkOptions(cmd, args, pol, noEnrich)
			if err != nil {
				return err
			}
			opts.FailOn = nil
			rep, err := check.Run(cmd.Context(), opts)
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("output") {
				output = pol.Gate.Baseline
			}
			b := policy.NewBaseline(rep.Findings, version, time.Now(), func(f model.Finding) (string, string) {
				return report.ID(f), report.Where(f)
			})
			if err := b.Write(output); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %d finding(s) to %s (%d suppressed findings excluded).\n",
				len(b.Findings), output, rep.Summary.Suppressed)
			if !pol.Gate.NewOnly {
				fmt.Fprintln(cmd.OutOrStdout(), "Enable it with `gate: {new_only: true}` in .fhub.yaml, or pass --new-only to fhub check.")
			}
			return nil
		},
	}
	create.Flags().StringVarP(&output, "output", "o", policy.DefaultBaselineFile, "baseline file to write (default: gate.baseline from the policy)")
	create.Flags().BoolVar(&noEnrich, "no-enrich", false, "skip exploit intelligence")
	bl.AddCommand(create)
	return bl
}

func newInitCmd() *cobra.Command {
	var force bool
	return &cobra.Command{
		Use:   "init",
		Short: "Write a starter " + policy.DefaultFile + " policy file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			if force {
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			}
			f, err := os.OpenFile(policy.DefaultFile, flags, 0o644)
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%s already exists (use --force to overwrite)", policy.DefaultFile)
			}
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := f.WriteString(policy.Template(time.Now())); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Wrote", policy.DefaultFile)
			return nil
		},
	}
}

func newDBCmd(g *globalFlags) *cobra.Command {
	db := &cobra.Command{
		Use:   "db",
		Short: "Manage the cached exploit-intelligence feeds (CISA KEV, FIRST EPSS)",
	}

	var force bool
	update := &cobra.Command{
		Use:   "update",
		Short: "Download the latest KEV and EPSS feeds",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			eo, err := g.enrichOptions(cmd)
			if err != nil {
				return err
			}
			if !force {
				eo.MaxAge = time.Minute // explicit update: refresh unless just done
			}
			st, err := enrich.Update(cmd.Context(), eo, force)
			if st != nil {
				printStatus(cmd, eo.CacheDir, st)
			}
			return err
		},
	}
	update.Flags().BoolVar(&force, "force", false, "re-download even if the cache is fresh")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show what exploit intelligence is cached",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			eo, err := g.enrichOptions(cmd)
			if err != nil {
				return err
			}
			st, err := enrich.Status(eo)
			if err != nil {
				return err
			}
			printStatus(cmd, eo.CacheDir, st)
			return nil
		},
	}
	db.AddCommand(update, status)
	return db
}

func printStatus(cmd *cobra.Command, dir string, st []enrich.SourceStatus) {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Cache:", dir)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FEED\tDATA DATE\tRECORDS\tFETCHED\tSTATE")
	for _, s := range st {
		if !s.Present {
			fmt.Fprintf(tw, "%s\t-\t-\t-\tmissing (run `fhub db update`)\n", s.Name)
			continue
		}
		state := "ok"
		if s.Stale {
			state = "STALE"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s ago\t%s\n", s.Name, s.DataDate, s.Records, s.Age.Round(time.Minute), state)
	}
	tw.Flush()
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
