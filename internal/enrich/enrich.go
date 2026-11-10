// Package enrich adds real-world exploit intelligence to findings:
//
//   - CISA KEV: is this CVE known to be exploited in the wild?
//   - FIRST EPSS: how likely is exploitation in the next 30 days?
//   - OSV: which CVE does a GHSA/PYSEC/GO/RUSTSEC advisory correspond to?
//
// Feeds are cached on disk so runs after the first work offline.
// The only data ever sent anywhere is public advisory IDs (to OSV).
package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// Sources are the feed locations. Override only for testing or mirrors.
type Sources struct {
	KEV  string
	EPSS string
	OSV  string // base URL; "/v1/vulns/<id>" is appended
}

// DefaultSources are the official public feeds (verified 2026-11).
var DefaultSources = Sources{
	KEV:  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
	EPSS: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
	OSV:  "https://api.osv.dev",
}

const (
	kevFile  = "kev.json"
	epssFile = "epss.csv.gz"
	osvFile  = "osv-aliases.json"

	maxKEVBytes  = 64 << 20
	maxEPSSBytes = 64 << 20
	maxOSVBytes  = 4 << 20

	// DefaultMaxAge: KEV and EPSS publish daily.
	DefaultMaxAge = 24 * time.Hour
	// StaleAfter: data older than this triggers a warning.
	StaleAfter = 72 * time.Hour
	osvTTL     = 7 * 24 * time.Hour
	osvWorkers = 8
)

// Options configures enrichment.
type Options struct {
	CacheDir string
	Offline  bool          // never touch the network
	MaxAge   time.Duration // refresh feeds older than this (0 = DefaultMaxAge)
	Sources  Sources       // zero value = DefaultSources
	Fetcher  *Fetcher
	Warn     func(string) // non-fatal problems; nil = ignore
	Now      func() time.Time
}

func (o *Options) defaults() {
	if o.MaxAge == 0 {
		o.MaxAge = DefaultMaxAge
	}
	if o.Sources == (Sources{}) {
		o.Sources = DefaultSources
	}
	if o.Fetcher == nil {
		o.Fetcher = NewFetcher("dev")
	}
	if o.Warn == nil {
		o.Warn = func(string) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// SourceStatus describes one cached feed for `fhub db status`.
type SourceStatus struct {
	Name     string        `json:"name"`
	Present  bool          `json:"present"`
	Fetched  time.Time     `json:"fetched_at,omitzero"`
	Age      time.Duration `json:"-"`
	DataDate string        `json:"data_date,omitempty"`
	Records  int           `json:"records"`
	Stale    bool          `json:"stale"`
}

// Info summarizes the intelligence used in a run (shown in reports).
type Info struct {
	Enabled     bool   `json:"enabled"`
	KEVVersion  string `json:"kev_version,omitempty"`
	EPSSDate    string `json:"epss_date,omitempty"`
	OSVLookups  int    `json:"osv_lookups,omitempty"`
	AliasesUsed int    `json:"aliases_added,omitempty"`
}

// Update refreshes the KEV and EPSS feeds. With force, cached ETags are
// ignored and data is re-downloaded even if fresh.
func Update(ctx context.Context, opts Options, force bool) ([]SourceStatus, error) {
	opts.defaults()
	if opts.Offline {
		return nil, errors.New("cannot update in offline mode")
	}
	c := cache{opts.CacheDir}
	meta, err := c.readMeta()
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, src := range []struct {
		name, file, url string
		max             int64
		validate        func([]byte) (string, int, error)
	}{
		{"kev", kevFile, opts.Sources.KEV, maxKEVBytes, validateKEV},
		{"epss", epssFile, opts.Sources.EPSS, maxEPSSBytes, validateEPSS},
	} {
		m := meta[src.name]
		if !force && m.SHA256 != "" && opts.Now().Sub(m.FetchedAt) < opts.MaxAge {
			continue // fresh enough
		}
		etag := m.ETag
		if force || m.SHA256 == "" {
			etag = ""
		} else if _, err := c.readVerified(src.file, m); err != nil {
			etag = "" // cached file is broken: download it again
		}
		resp, err := opts.Fetcher.get(ctx, src.url, etag, src.max)
		if errors.Is(err, errNotModified) {
			m.FetchedAt = opts.Now()
			meta[src.name] = m
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
			continue
		}
		// Validate BEFORE replacing the cache: a bad download never
		// clobbers good data.
		date, records, err := src.validate(resp.Body)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
			continue
		}
		if err := c.writeAtomic(src.file, resp.Body); err != nil {
			return nil, err
		}
		meta[src.name] = SourceMeta{
			URL: src.url, FetchedAt: opts.Now(), ETag: resp.ETag,
			SHA256: sha(resp.Body), Bytes: len(resp.Body), DataDate: date, Records: records,
		}
	}
	if err := c.writeMeta(meta); err != nil {
		return nil, err
	}
	st, _ := Status(opts)
	return st, errors.Join(errs...)
}

func validateKEV(b []byte) (string, int, error) {
	m, ver, err := parseKEV(b)
	return ver, len(m), err
}

func validateEPSS(b []byte) (string, int, error) {
	return scanEPSS(b, map[string]bool{}, func(string, model.EPSS) {})
}

// Status reports what is cached.
func Status(opts Options) ([]SourceStatus, error) {
	opts.defaults()
	meta, err := cache{opts.CacheDir}.readMeta()
	if err != nil {
		return nil, err
	}
	var out []SourceStatus
	for _, name := range []string{"kev", "epss"} {
		m, ok := meta[name]
		s := SourceStatus{Name: name, Present: ok && m.SHA256 != ""}
		if s.Present {
			s.Fetched, s.DataDate, s.Records = m.FetchedAt, m.DataDate, m.Records
			s.Age = opts.Now().Sub(m.FetchedAt)
			s.Stale = s.Age > StaleAfter
		}
		out = append(out, s)
	}
	return out, nil
}

// Enricher applies cached intelligence to findings.
type Enricher struct {
	opts    Options
	kev     map[string]model.KEV
	kevVer  string
	epss    []byte // gzipped feed, scanned on demand
	epssDay string
	info    Info
}

// Open prepares an Enricher. Unless Offline, it first refreshes feeds older
// than MaxAge. If a refresh fails but older data is cached, it warns and
// uses the old data. If no data is available at all it returns an error,
// because silently ranking without exploit data could hide a P0.
func Open(ctx context.Context, opts Options) (*Enricher, error) {
	opts.defaults()
	if !opts.Offline {
		if _, err := Update(ctx, opts, false); err != nil {
			opts.Warn("could not refresh exploit intelligence, using cached data if present: " + err.Error())
		}
	}
	c := cache{opts.CacheDir}
	meta, err := c.readMeta()
	if err != nil {
		return nil, err
	}
	e := &Enricher{opts: opts, info: Info{Enabled: true}}
	var missing []string

	if b, err := c.readVerified(kevFile, meta["kev"]); err == nil {
		if e.kev, e.kevVer, err = parseKEV(b); err != nil {
			return nil, err
		}
		e.info.KEVVersion = e.kevVer
	} else {
		missing = append(missing, "CISA KEV")
	}
	if b, err := c.readVerified(epssFile, meta["epss"]); err == nil {
		e.epss, e.epssDay = b, meta["epss"].DataDate
		e.info.EPSSDate = e.epssDay
	} else {
		missing = append(missing, "EPSS")
	}
	if len(missing) > 0 {
		hint := "run `fhub db update`"
		if opts.Offline {
			hint = "run `fhub db update` while online, or copy a cache directory into place"
		}
		return nil, fmt.Errorf("no cached %s data (%s), or pass --no-enrich to rank by severity only", strings.Join(missing, " and "), hint)
	}
	for _, s := range must(Status(opts)) {
		if s.Stale {
			opts.Warn(fmt.Sprintf("%s data is %s old; rankings may be outdated", strings.ToUpper(s.Name), s.Age.Round(time.Hour)))
		}
	}
	return e, nil
}

func must[T any](v T, _ error) T { return v }

// Info describes the data used.
func (e *Enricher) Info() Info { return e.info }

// Apply sets KEV and EPSS on vulnerability findings, in place. For findings
// with several CVEs, KEV matches on any of them and EPSS takes the maximum.
func (e *Enricher) Apply(fs []model.Finding) error {
	want := map[string]bool{}
	for i := range fs {
		for _, id := range cves(fs[i]) {
			want[id] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	scores := map[string]model.EPSS{}
	if _, _, err := scanEPSS(e.epss, want, func(cve string, s model.EPSS) { scores[cve] = s }); err != nil {
		return err
	}
	for i := range fs {
		f := &fs[i]
		for _, id := range cves(*f) {
			if k, ok := e.kev[id]; ok && f.KEV == nil {
				f.KEV = &k
			}
			if s, ok := scores[id]; ok && (f.EPSS == nil || s.Score > f.EPSS.Score) {
				f.EPSS = &s
			}
		}
	}
	return nil
}

func cves(f model.Finding) []string {
	if f.Kind != model.KindVuln {
		return nil
	}
	var out []string
	for _, id := range append([]string{f.VulnID}, f.Aliases...) {
		if u := strings.ToUpper(id); strings.HasPrefix(u, "CVE-") {
			out = append(out, u)
		}
	}
	return out
}

// osvIDPattern matches advisory IDs that OSV can resolve to CVEs.
var osvIDPattern = regexp.MustCompile(`^(GHSA|PYSEC|GO|RUSTSEC|OSV|GSD|RUBYSEC|PHSA|BIT)-[A-Za-z0-9._-]+$`)

type osvEntry struct {
	Aliases   []string  `json:"aliases"`
	FetchedAt time.Time `json:"fetched_at"`
}

// AddAliases resolves non-CVE advisory IDs through OSV for vulnerability
// findings that have no CVE yet, and appends the aliases. Run it BEFORE
// dedupe so fingerprints use the final canonical ID. Results are cached
// (including "no aliases"); offline it uses the cache only.
func (e *Enricher) AddAliases(ctx context.Context, fs []model.Finding) {
	c := cache{e.opts.CacheDir}
	known := map[string]osvEntry{}
	if b, err := os.ReadFile(c.path(osvFile)); err == nil {
		_ = json.Unmarshal(b, &known)
	}

	var lookup []string
	need := map[string]bool{}
	for _, f := range fs {
		if f.Kind != model.KindVuln || len(cves(f)) > 0 {
			continue
		}
		for _, id := range append([]string{f.VulnID}, f.Aliases...) {
			if !osvIDPattern.MatchString(id) || need[id] {
				continue
			}
			need[id] = true
			if k, ok := known[id]; !ok || e.opts.Now().Sub(k.FetchedAt) > osvTTL {
				lookup = append(lookup, id)
			}
		}
	}

	if len(lookup) > 0 && !e.opts.Offline {
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, osvWorkers)
		var failed int
		for _, id := range lookup {
			wg.Add(1)
			sem <- struct{}{}
			go func(id string) {
				defer wg.Done()
				defer func() { <-sem }()
				u := strings.TrimRight(e.opts.Sources.OSV, "/") + "/v1/vulns/" + url.PathEscape(id)
				resp, err := e.opts.Fetcher.get(ctx, u, "", maxOSVBytes)
				var aliases []string
				switch {
				case errors.Is(err, errNotFound):
					// Unknown to OSV: cache the negative answer.
				case err != nil:
					mu.Lock()
					failed++
					mu.Unlock()
					return
				default:
					if aliases, err = parseOSV(resp.Body); err != nil {
						mu.Lock()
						failed++
						mu.Unlock()
						return
					}
				}
				mu.Lock()
				known[id] = osvEntry{Aliases: aliases, FetchedAt: e.opts.Now()}
				e.info.OSVLookups++
				mu.Unlock()
			}(id)
		}
		wg.Wait()
		if failed > 0 {
			e.opts.Warn(fmt.Sprintf("OSV alias lookup failed for %d advisory ID(s); some duplicates may not merge", failed))
		}
		if b, err := json.Marshal(known); err == nil {
			_ = c.writeAtomic(osvFile, b)
		}
	}

	for i := range fs {
		f := &fs[i]
		if f.Kind != model.KindVuln || len(cves(*f)) > 0 {
			continue
		}
		have := map[string]bool{strings.ToUpper(f.VulnID): true}
		for _, a := range f.Aliases {
			have[strings.ToUpper(a)] = true
		}
		for _, id := range append([]string{f.VulnID}, f.Aliases...) {
			for _, a := range known[id].Aliases {
				if !have[strings.ToUpper(a)] {
					have[strings.ToUpper(a)] = true
					f.Aliases = append(f.Aliases, a)
					e.info.AliasesUsed++
				}
			}
		}
	}
}
