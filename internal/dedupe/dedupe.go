// Package dedupe assigns stable fingerprints and merges findings that
// different scanners (or the same scanner twice) reported for the same issue.
package dedupe

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// Merge fingerprints and deduplicates findings. Input order is preserved for
// the first occurrence of each merged group.
func Merge(in []model.Finding) []model.Finding {
	var vulns, other []model.Finding
	for _, f := range in {
		if f.Kind == model.KindVuln {
			vulns = append(vulns, f)
		} else {
			other = append(other, f)
		}
	}
	out := mergeVulns(vulns)
	return append(out, mergeByFingerprint(other)...)
}

// mergeVulns groups vulnerabilities per package, then joins any findings
// whose ID sets overlap (union-find). This is what lets Trivy's "CVE-x" and
// Grype's "GHSA-y (related: CVE-x)" collapse into one finding.
func mergeVulns(fs []model.Finding) []model.Finding {
	byPkg := map[string][]int{}
	var pkgOrder []string
	for i, f := range fs {
		k := packageKey(f)
		if _, seen := byPkg[k]; !seen {
			pkgOrder = append(pkgOrder, k)
		}
		byPkg[k] = append(byPkg[k], i)
	}

	var out []model.Finding
	for _, pk := range pkgOrder {
		idx := byPkg[pk]
		uf := newUnionFind(len(idx))
		owner := map[string]int{} // vuln ID -> position in idx
		for pos, i := range idx {
			for _, id := range ids(fs[i]) {
				if prev, ok := owner[id]; ok {
					uf.union(prev, pos)
				} else {
					owner[id] = pos
				}
			}
		}
		groups := map[int][]int{}
		var rootOrder []int
		for pos := range idx {
			r := uf.find(pos)
			if _, ok := groups[r]; !ok {
				rootOrder = append(rootOrder, r)
			}
			groups[r] = append(groups[r], idx[pos])
		}
		for _, r := range rootOrder {
			m := fs[groups[r][0]]
			for _, i := range groups[r][1:] {
				m = combine(m, fs[i])
			}
			setCanonicalID(&m)
			// NOTE: the canonical ID can improve once OSV alias enrichment
			// lands (GHSA -> CVE), which would change this fingerprint. Alias
			// enrichment must therefore run before dedupe.
			m.Fingerprint = hash("vuln", pk, m.VulnID)
			out = append(out, m)
		}
	}
	return out
}

func mergeByFingerprint(fs []model.Finding) []model.Finding {
	byFP := map[string]int{}
	var out []model.Finding
	for _, f := range fs {
		f.Fingerprint = fingerprint(f)
		if i, ok := byFP[f.Fingerprint]; ok {
			out[i] = combine(out[i], f)
			continue
		}
		byFP[f.Fingerprint] = len(out)
		out = append(out, f)
	}
	return out
}

// fingerprint for code/secret/iac findings: rule + file + content hash,
// falling back to the line number when there is no content to hash.
//
// Secrets are the exception: scanners name the same secret differently
// (gitleaks "aws-access-token" vs Trivy "aws-access-key-id") and some mask the
// value, so a secret is identified by file + line only. That way one leaked
// key is one finding, whichever scanners reported it.
func fingerprint(f model.Finding) string {
	var path, anchor string
	if f.Location != nil {
		path = strings.ToLower(f.Location.Path)
		anchor = "L" + strconv.Itoa(f.Location.StartLine)
	}
	if f.Kind == model.KindSecret {
		if f.Location != nil && f.Location.StartLine > 0 {
			return hash(string(f.Kind), path, anchor)
		}
		return hash(string(f.Kind), strings.ToLower(f.RuleID), path, f.MatchHash)
	}
	if f.MatchHash != "" {
		anchor = f.MatchHash
	}
	return hash(string(f.Kind), strings.ToLower(f.RuleID), path, anchor)
}

// packageKey identifies a package version independent of purl qualifiers,
// which scanners fill in differently (arch, distro, ...).
func packageKey(f model.Finding) string {
	p := f.Package
	if p == nil {
		if f.Location != nil {
			return "loc:" + strings.ToLower(f.Location.Path)
		}
		return "unknown"
	}
	if p.PURL != "" {
		k := p.PURL
		if i := strings.IndexAny(k, "?#"); i >= 0 {
			k = k[:i]
		}
		return strings.ToLower(k)
	}
	return strings.ToLower(p.Ecosystem + "/" + p.Name + "@" + p.Version)
}

func ids(f model.Finding) []string {
	out := make([]string, 0, 1+len(f.Aliases))
	if f.VulnID != "" {
		out = append(out, strings.ToUpper(f.VulnID))
	}
	for _, a := range f.Aliases {
		out = append(out, strings.ToUpper(a))
	}
	return out
}

// setCanonicalID picks the canonical ID (CVE > GHSA > other, then
// lexicographic) and moves every other ID into Aliases.
func setCanonicalID(f *model.Finding) {
	all := map[string]string{} // upper -> original spelling
	for _, id := range append([]string{f.VulnID}, f.Aliases...) {
		if id != "" {
			if _, ok := all[strings.ToUpper(id)]; !ok {
				all[strings.ToUpper(id)] = id
			}
		}
	}
	if len(all) == 0 {
		return
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	rank := func(id string) int {
		switch {
		case strings.HasPrefix(id, "CVE-"):
			return 0
		case strings.HasPrefix(id, "GHSA-"):
			return 1
		default:
			return 2
		}
	}
	slices.SortFunc(keys, func(a, b string) int {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra - rb
		}
		return strings.Compare(a, b)
	})
	f.VulnID = all[keys[0]]
	f.Aliases = f.Aliases[:0:0]
	for _, k := range keys[1:] {
		f.Aliases = append(f.Aliases, all[k])
	}
	if f.Title == "" || strings.EqualFold(f.Title, all[keys[0]]) || containsFold(keys, f.Title) {
		f.Title = f.VulnID
	}
}

// combine merges b into a. a wins for descriptive fields; severity and CVSS
// take the maximum; sources and aliases are unioned.
func combine(a, b model.Finding) model.Finding {
	if a.Severity < b.Severity {
		a.Severity = b.Severity
	}
	a.CVSS = max(a.CVSS, b.CVSS)
	// Prefer a human title over a bare ID.
	if (a.Title == "" || isBareID(a.Title)) && b.Title != "" && !isBareID(b.Title) {
		a.Title = b.Title
	}
	if a.Description == "" {
		a.Description = b.Description
	}
	if a.URL == "" {
		a.URL = b.URL
	}
	if a.VulnID == "" {
		a.VulnID = b.VulnID
	} else if b.VulnID != "" && !strings.EqualFold(a.VulnID, b.VulnID) {
		a.Aliases = append(a.Aliases, b.VulnID)
	}
	a.Aliases = append(a.Aliases, b.Aliases...)
	if a.Package == nil {
		a.Package = b.Package
	} else if b.Package != nil {
		p := *a.Package
		if p.FixedVersion == "" {
			p.FixedVersion = b.Package.FixedVersion
		}
		if p.PURL == "" {
			p.PURL = b.Package.PURL
		}
		if p.Scope == "" {
			p.Scope = b.Package.Scope
		}
		a.Package = &p
	}
	if a.Location == nil {
		a.Location = b.Location
	}
	if a.RuleID == "" {
		a.RuleID = b.RuleID
	}
	for _, s := range b.Sources {
		if !slices.ContainsFunc(a.Sources, func(x model.Source) bool {
			return x.Scanner == s.Scanner && x.RuleID == s.RuleID && x.File == s.File
		}) {
			a.Sources = append(a.Sources, s)
		}
	}
	return a
}

func isBareID(s string) bool {
	u := strings.ToUpper(s)
	return strings.HasPrefix(u, "CVE-") || strings.HasPrefix(u, "GHSA-")
}

func containsFold(keys []string, s string) bool {
	return slices.Contains(keys, strings.ToUpper(s))
}

func hash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

type unionFind struct{ parent []int }

func newUnionFind(n int) *unionFind {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	return &unionFind{p}
}

func (u *unionFind) find(x int) int {
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b int) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[rb] = ra
	}
}
