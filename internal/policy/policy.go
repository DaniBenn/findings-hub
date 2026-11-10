// Package policy loads .fhub.yaml and applies its decisions: gate settings,
// prioritization thresholds, expiring suppressions and baselines.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/DaniBenn/findings-hub/internal/model"
	"github.com/DaniBenn/findings-hub/internal/prioritize"
)

// DefaultFile is looked up in the working directory when --policy is not given.
const DefaultFile = ".fhub.yaml"

// MaxSuppressionDays caps how far in the future a suppression may expire.
// Accepted risk must be re-reviewed at least yearly.
const MaxSuppressionDays = 366

// Policy is the parsed .fhub.yaml.
type Policy struct {
	Version      int           `yaml:"version"`
	Gate         Gate          `yaml:"gate"`
	Prioritize   Prioritize    `yaml:"prioritize"`
	Suppressions []Suppression `yaml:"suppressions"`

	// Source is the file the policy came from ("" = built-in defaults).
	Source string `yaml:"-"`
}

// Gate controls what fails the build.
type Gate struct {
	FailOn []string `yaml:"fail_on"`
	// NewOnly: findings in the baseline do not fail the gate, unless they
	// have escalated since (e.g. newly added to CISA KEV).
	NewOnly  bool   `yaml:"new_only"`
	Baseline string `yaml:"baseline"`
}

// Prioritize overrides prioritize.DefaultConfig. Pointers distinguish
// "not set" from zero.
type Prioritize struct {
	EPSSP0       *float64 `yaml:"epss_p0"`
	EPSSP1       *float64 `yaml:"epss_p1"`
	DowngradeDev *bool    `yaml:"downgrade_dev"`
}

// Suppression is one accepted-risk entry. At least one of ID, Fingerprint
// or Path must be set; all set matchers must match.
type Suppression struct {
	ID          string `yaml:"id"`          // CVE/GHSA/alias or scanner rule ID
	Fingerprint string `yaml:"fingerprint"` // exact finding fingerprint
	Package     string `yaml:"package"`     // purl ("pkg:npm/lodash[@ver]") or package name
	Path        string `yaml:"path"`        // glob; ** matches across directories
	Reason      string `yaml:"reason"`
	Expires     string `yaml:"expires"` // YYYY-MM-DD, inclusive
	VEX         *VEX   `yaml:"vex"`

	expires time.Time
	path    *glob
}

// VEX carries an OpenVEX statement for the suppression.
type VEX struct {
	Status        string `yaml:"status"`
	Justification string `yaml:"justification"`
}

var (
	vexStatuses       = []string{"not_affected", "affected", "fixed", "under_investigation"}
	vexJustifications = []string{
		"component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist",
	}
)

// Default returns the policy used when no file exists.
func Default() *Policy {
	return &Policy{Version: 1, Gate: Gate{FailOn: []string{"P0"}, Baseline: DefaultBaselineFile}}
}

// Load reads and validates a policy file. If path is "" it looks for
// DefaultFile and falls back to Default() when that does not exist.
func Load(path string, now time.Time) (*Policy, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultFile
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p, err := Parse(b, now)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Source = path
	return p, nil
}

// Parse decodes and validates policy YAML. Unknown keys are errors, so a
// typo like "suppresions:" can never silently disable a policy.
func Parse(b []byte, now time.Time) (*Policy, error) {
	p := Default()
	p.Gate.FailOn = nil
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(p); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if p.Gate.FailOn == nil {
		p.Gate.FailOn = []string{"P0"}
	}
	if p.Gate.Baseline == "" {
		p.Gate.Baseline = DefaultBaselineFile
	}
	return p, p.validate(now)
}

func (p *Policy) validate(now time.Time) error {
	var errs []error
	if p.Version != 1 {
		errs = append(errs, fmt.Errorf("version: must be 1 (got %d)", p.Version))
	}
	for _, s := range p.Gate.FailOn {
		if _, err := model.ParsePriority(s); err != nil {
			errs = append(errs, fmt.Errorf("gate.fail_on: %w", err))
		}
	}
	for name, v := range map[string]*float64{"epss_p0": p.Prioritize.EPSSP0, "epss_p1": p.Prioritize.EPSSP1} {
		if v != nil && (*v < 0 || *v > 1) {
			errs = append(errs, fmt.Errorf("prioritize.%s: must be between 0 and 1", name))
		}
	}
	today := day(now)
	for i := range p.Suppressions {
		s := &p.Suppressions[i]
		at := fmt.Sprintf("suppressions[%d]", i)
		if s.ID == "" && s.Fingerprint == "" && s.Path == "" {
			errs = append(errs, fmt.Errorf("%s: needs at least one of id, fingerprint or path", at))
		}
		if strings.TrimSpace(s.Reason) == "" {
			errs = append(errs, fmt.Errorf("%s: reason is required (why is this risk accepted?)", at))
		}
		if s.Expires == "" {
			errs = append(errs, fmt.Errorf("%s: expires is required (YYYY-MM-DD); permanent ignores are not allowed", at))
		} else if t, err := time.Parse(time.DateOnly, s.Expires); err != nil {
			errs = append(errs, fmt.Errorf("%s: expires %q is not a YYYY-MM-DD date", at, s.Expires))
		} else {
			s.expires = t
			if t.Sub(today) > MaxSuppressionDays*24*time.Hour {
				errs = append(errs, fmt.Errorf("%s: expires %s is more than %d days away; re-review accepted risk at least yearly", at, s.Expires, MaxSuppressionDays))
			}
		}
		if s.Path != "" {
			g, err := compileGlob(s.Path)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: path: %w", at, err))
			}
			s.path = g
		}
		if s.VEX != nil {
			if !contains(vexStatuses, s.VEX.Status) {
				errs = append(errs, fmt.Errorf("%s: vex.status must be one of %s", at, strings.Join(vexStatuses, ", ")))
			}
			if s.VEX.Status == "not_affected" && !contains(vexJustifications, s.VEX.Justification) {
				errs = append(errs, fmt.Errorf("%s: vex.justification is required for not_affected and must be one of %s", at, strings.Join(vexJustifications, ", ")))
			}
		}
	}
	return errors.Join(errs...)
}

// FailOn returns the gate priorities.
func (p *Policy) FailOn() []model.Priority {
	var out []model.Priority
	for _, s := range p.Gate.FailOn {
		if pr, err := model.ParsePriority(s); err == nil {
			out = append(out, pr)
		}
	}
	return out
}

// PrioritizeConfig merges the policy's overrides onto the defaults.
func (p *Policy) PrioritizeConfig() prioritize.Config {
	c := prioritize.DefaultConfig()
	if v := p.Prioritize.EPSSP0; v != nil {
		c.EPSSP0 = *v
	}
	if v := p.Prioritize.EPSSP1; v != nil {
		c.EPSSP1 = *v
	}
	if v := p.Prioritize.DowngradeDev; v != nil {
		c.DowngradeDev = *v
	}
	return c
}

func day(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
