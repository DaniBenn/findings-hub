package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// DefaultBaselineFile is committed next to .fhub.yaml.
const DefaultBaselineFile = ".fhub-baseline.json"

// Baseline is a snapshot of accepted pre-existing findings, so a team can
// adopt the gate on a legacy codebase and fail only on new issues.
type Baseline struct {
	SchemaVersion int             `json:"schema_version"`
	CreatedAt     time.Time       `json:"created_at"`
	ToolVersion   string          `json:"tool_version,omitempty"`
	Findings      []BaselineEntry `json:"findings"`

	byFP map[string]BaselineEntry
}

// BaselineEntry is one baselined finding. ID/Where are for humans reviewing
// the file in a PR; only Fingerprint and Priority are used for matching.
type BaselineEntry struct {
	Fingerprint string         `json:"fingerprint"`
	Priority    model.Priority `json:"priority"`
	ID          string         `json:"id,omitempty"`
	Where       string         `json:"where,omitempty"`
}

// NewBaseline snapshots every open finding.
func NewBaseline(fs []model.Finding, toolVersion string, now time.Time, describe func(model.Finding) (id, where string)) *Baseline {
	b := &Baseline{SchemaVersion: 1, CreatedAt: now.UTC().Truncate(time.Second), ToolVersion: toolVersion, Findings: []BaselineEntry{}}
	seen := map[string]bool{}
	for _, f := range fs {
		if f.Status == model.StatusSuppressed || seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		id, where := describe(f)
		b.Findings = append(b.Findings, BaselineEntry{Fingerprint: f.Fingerprint, Priority: f.Priority, ID: id, Where: where})
	}
	// Stable order keeps baseline diffs reviewable.
	slices.SortFunc(b.Findings, func(x, y BaselineEntry) int { return strings.Compare(x.Fingerprint, y.Fingerprint) })
	return b
}

// LoadBaseline reads a baseline file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("baseline %s not found: create it with `fhub baseline create <scanner-output>...`", path)
	}
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	if b.SchemaVersion != 1 {
		return nil, fmt.Errorf("baseline %s: unsupported schema_version %d", path, b.SchemaVersion)
	}
	return &b, nil
}

// Write saves the baseline as indented JSON.
func (b *Baseline) Write(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// BaselineResult reports what the baseline did.
type BaselineResult struct {
	Baselined int
	Escalated int
}

// Apply marks open findings that are in the baseline as baselined, in place.
// A baselined finding whose priority has become more urgent AND now hits the
// gate stays open: a baseline must never hide an issue that started being
// exploited after it was accepted.
func (b *Baseline) Apply(fs []model.Finding, failOn []model.Priority) BaselineResult {
	if b.byFP == nil {
		b.byFP = make(map[string]BaselineEntry, len(b.Findings))
		for _, e := range b.Findings {
			b.byFP[e.Fingerprint] = e
		}
	}
	var res BaselineResult
	for i := range fs {
		f := &fs[i]
		if f.Status != model.StatusOpen {
			continue
		}
		e, ok := b.byFP[f.Fingerprint]
		if !ok {
			continue
		}
		if e.Priority != model.PriorityUnset && f.Priority < e.Priority && slices.Contains(failOn, f.Priority) {
			f.Reasons = append([]string{fmt.Sprintf("escalated since baseline (was %s)", e.Priority)}, f.Reasons...)
			res.Escalated++
			continue
		}
		f.Status = model.StatusBaselined
		res.Baselined++
	}
	return res
}
