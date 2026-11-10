package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// ExpiringSoon: suppressions expiring within this window produce a warning.
const ExpiringSoon = 14 * 24 * time.Hour

// SuppressResult reports what the suppressions did, for warnings and summary.
type SuppressResult struct {
	Suppressed   int
	Expired      []string // human-readable descriptions of expired suppressions that matched
	ExpiringSoon []string
	Unused       []string // suppressions that matched nothing: candidates for cleanup
}

// ApplySuppressions marks matching open findings as suppressed, in place.
// Expired suppressions never suppress: the finding stays open with a reason
// explaining that its accepted-risk decision lapsed.
func (p *Policy) ApplySuppressions(fs []model.Finding, now time.Time) SuppressResult {
	var res SuppressResult
	today := day(now)
	used := make([]bool, len(p.Suppressions))

	for i := range fs {
		f := &fs[i]
		if f.Status == "" {
			f.Status = model.StatusOpen
		}
		if f.Status != model.StatusOpen {
			continue
		}
		for j := range p.Suppressions {
			s := &p.Suppressions[j]
			if !s.matches(f) {
				continue
			}
			used[j] = true
			if today.After(s.expires) {
				f.Reasons = append(f.Reasons, fmt.Sprintf("suppression expired on %s (was: %q): renew it or fix the issue", s.Expires, s.Reason))
				res.Expired = append(res.Expired, fmt.Sprintf("%s expired %s", s.describe(), s.Expires))
				continue
			}
			f.Status = model.StatusSuppressed
			f.Suppression = &model.Suppression{Reason: s.Reason, Expires: s.Expires}
			if s.VEX != nil {
				f.Suppression.VEXStatus, f.Suppression.VEXJustification = s.VEX.Status, s.VEX.Justification
			}
			res.Suppressed++
			if s.expires.Sub(today) <= ExpiringSoon {
				res.ExpiringSoon = append(res.ExpiringSoon, fmt.Sprintf("%s expires %s", s.describe(), s.Expires))
			}
			break
		}
	}
	for j, u := range used {
		if !u {
			res.Unused = append(res.Unused, p.Suppressions[j].describe())
		}
	}
	res.Expired = dedupStrings(res.Expired)
	res.ExpiringSoon = dedupStrings(res.ExpiringSoon)
	return res
}

func (s *Suppression) matches(f *model.Finding) bool {
	if s.ID != "" && !matchID(s.ID, f) {
		return false
	}
	if s.Fingerprint != "" && !strings.EqualFold(s.Fingerprint, f.Fingerprint) {
		return false
	}
	if s.Package != "" && !matchPackage(s.Package, f.Package) {
		return false
	}
	if s.path != nil && (f.Location == nil || !s.path.match(f.Location.Path)) {
		return false
	}
	return true
}

func matchID(id string, f *model.Finding) bool {
	if strings.EqualFold(id, f.VulnID) || strings.EqualFold(id, f.RuleID) {
		return true
	}
	for _, a := range f.Aliases {
		if strings.EqualFold(id, a) {
			return true
		}
	}
	return false
}

// matchPackage: "pkg:npm/lodash" matches any version, "pkg:npm/lodash@4.17.20"
// one version (purl qualifiers are ignored); a bare name matches Package.Name.
func matchPackage(pattern string, p *model.Package) bool {
	if p == nil {
		return false
	}
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if !strings.HasPrefix(pattern, "pkg:") {
		return pattern == strings.ToLower(p.Name)
	}
	key := strings.ToLower(p.PURL)
	if i := strings.IndexAny(key, "?#"); i >= 0 {
		key = key[:i]
	}
	if strings.Contains(pattern, "@") {
		return key == pattern
	}
	name, _, _ := strings.Cut(key, "@")
	return name == pattern
}

func (s *Suppression) describe() string {
	var parts []string
	for _, kv := range [][2]string{{"id", s.ID}, {"fingerprint", s.Fingerprint}, {"package", s.Package}, {"path", s.Path}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	return "suppression(" + strings.Join(parts, " ") + ")"
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
