package enrich

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DaniBenn/findings-hub/internal/model"
)

var ctx = context.Background()

func vuln(id string, aliases ...string) model.Finding {
	return model.Finding{Kind: model.KindVuln, VulnID: id, Aliases: aliases}
}

func TestUpdateThenApply(t *testing.T) {
	srv := newFeedServer(t)
	opts := srv.options(t, t.TempDir())

	st, err := Update(ctx, opts, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range st {
		if !s.Present || s.Records == 0 || s.Stale {
			t.Errorf("bad status after update: %+v", s)
		}
	}
	if st[0].DataDate != "2026.11.09" || st[1].DataDate != "2026-11-09" {
		t.Errorf("data dates = %q / %q", st[0].DataDate, st[1].DataDate)
	}

	e, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	fs := []model.Finding{
		vuln("CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"),
		vuln("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"),
		vuln("CVE-2099-0001"),
		{Kind: model.KindCode, RuleID: "CVE-2021-44228"}, // non-vulns are never enriched
	}
	if err := e.Apply(fs); err != nil {
		t.Fatal(err)
	}
	if fs[0].KEV == nil || !fs[0].KEV.Ransomware || fs[0].KEV.DateAdded != "2021-12-10" {
		t.Errorf("log4j KEV = %+v", fs[0].KEV)
	}
	if fs[0].EPSS == nil || fs[0].EPSS.Score != 0.99999 || fs[0].EPSS.Date != "2026-11-09" {
		t.Errorf("log4j EPSS = %+v", fs[0].EPSS)
	}
	if fs[1].KEV != nil || fs[1].EPSS == nil || fs[1].EPSS.Score != 0.0525 {
		t.Errorf("lodash via alias: KEV=%+v EPSS=%+v", fs[1].KEV, fs[1].EPSS)
	}
	if fs[2].KEV != nil || fs[2].EPSS != nil {
		t.Errorf("unknown CVE got data")
	}
	if fs[3].KEV != nil || fs[3].EPSS != nil {
		t.Errorf("code finding was enriched")
	}
}

func TestEPSSTakesMaxAcrossCVEs(t *testing.T) {
	srv := newFeedServer(t)
	opts := srv.options(t, t.TempDir())
	e, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	fs := []model.Finding{vuln("CVE-2022-25883", "CVE-2014-0160")}
	e.Apply(fs)
	if fs[0].EPSS.Score != 0.9442 || fs[0].KEV == nil {
		t.Errorf("EPSS=%+v KEV=%+v", fs[0].EPSS, fs[0].KEV)
	}
}

func TestFreshCacheSkipsNetworkAndETag(t *testing.T) {
	srv := newFeedServer(t)
	opts := srv.options(t, t.TempDir())
	if _, err := Open(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if n := srv.hits["kev"].Load(); n != 1 {
		t.Errorf("fresh cache should not refetch: %d KEV requests", n)
	}
	// Force-expire: KEV comes back 304 via ETag, cache stays valid.
	opts.MaxAge = time.Nanosecond
	if _, err := Update(ctx, opts, false); err != nil {
		t.Fatal(err)
	}
	if n := srv.hits["kev"].Load(); n != 2 {
		t.Errorf("expected conditional refetch, got %d KEV requests", n)
	}
	if _, err := Open(ctx, Options{CacheDir: opts.CacheDir, Offline: true}); err != nil {
		t.Fatalf("cache unusable after 304: %v", err)
	}
}

func TestOfflineNeverTouchesNetwork(t *testing.T) {
	srv := newFeedServer(t)
	dir := t.TempDir()
	opts := srv.options(t, dir)
	opts.Offline = true
	if _, err := Open(ctx, opts); err == nil || !strings.Contains(err.Error(), "--no-enrich") {
		t.Fatalf("offline with empty cache should fail with a hint, got %v", err)
	}
	if _, err := Update(ctx, opts, false); err == nil {
		t.Fatal("update must refuse offline mode")
	}
	for name, h := range srv.hits {
		if h.Load() != 0 {
			t.Errorf("offline mode hit %s %d times", name, h.Load())
		}
	}
}

func TestFailedRefreshKeepsOldData(t *testing.T) {
	srv := newFeedServer(t)
	opts := srv.options(t, t.TempDir())
	if _, err := Update(ctx, opts, false); err != nil {
		t.Fatal(err)
	}
	srv.failKEV.Store(true)
	var warned bool
	opts.Warn = func(string) { warned = true }
	opts.MaxAge = time.Nanosecond
	e, err := Open(ctx, opts)
	if err != nil {
		t.Fatalf("should fall back to cached data: %v", err)
	}
	if !warned {
		t.Error("expected a warning about the failed refresh")
	}
	fs := []model.Finding{vuln("CVE-2021-44228")}
	e.Apply(fs)
	if fs[0].KEV == nil {
		t.Error("cached KEV data not used")
	}
}

func TestInvalidDownloadDoesNotClobberCache(t *testing.T) {
	srv := newFeedServer(t)
	opts := srv.options(t, t.TempDir())
	if _, err := Update(ctx, opts, false); err != nil {
		t.Fatal(err)
	}
	srv.corruptKEV.Store(true)
	if _, err := Update(ctx, opts, true); err == nil {
		t.Fatal("expected validation error for empty KEV catalog")
	}
	opts.Offline = true
	e, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	fs := []model.Finding{vuln("CVE-2021-44228")}
	e.Apply(fs)
	if fs[0].KEV == nil {
		t.Error("good KEV data was replaced by a bad download")
	}
}

func TestTamperedCacheDetected(t *testing.T) {
	srv := newFeedServer(t)
	dir := t.TempDir()
	opts := srv.options(t, dir)
	if _, err := Update(ctx, opts, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, kevFile), []byte(`{"vulnerabilities":[{"cveID":"CVE-2000-0001"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, Options{CacheDir: dir, Offline: true}); err == nil {
		t.Fatal("tampered cache should be rejected")
	}
}

func TestOSVAliases(t *testing.T) {
	srv := newFeedServer(t)
	opts := srv.options(t, t.TempDir())
	e, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	fs := []model.Finding{
		vuln("GHSA-35jh-r3h4-6jhm"),                   // resolvable
		vuln("GHSA-zzzz-zzzz-zzzz"),                   // unknown to OSV -> negative cache
		vuln("CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"), // already has a CVE: no lookup
		vuln("NOT AN ID; DROP TABLE"),                 // never sent anywhere
	}
	e.AddAliases(ctx, fs)
	if len(fs[0].Aliases) != 1 || fs[0].Aliases[0] != "CVE-2021-23337" {
		t.Errorf("aliases = %v", fs[0].Aliases)
	}
	if n := srv.hits["osv"].Load(); n != 2 {
		t.Errorf("OSV requests = %d, want 2", n)
	}

	// Second run: both answers (positive and negative) come from cache.
	e2, _ := Open(ctx, opts)
	fs2 := []model.Finding{vuln("GHSA-35jh-r3h4-6jhm"), vuln("GHSA-zzzz-zzzz-zzzz")}
	e2.AddAliases(ctx, fs2)
	if n := srv.hits["osv"].Load(); n != 2 {
		t.Errorf("OSV cache not used: %d requests", n)
	}
	if len(fs2[0].Aliases) != 1 {
		t.Errorf("cached aliases not applied: %v", fs2[0].Aliases)
	}
}

func TestCheckURL(t *testing.T) {
	ok := []string{"https://www.cisa.gov/x", "http://127.0.0.1:8080/x", "http://localhost/x", "http://[::1]/x"}
	bad := []string{"http://www.cisa.gov/x", "ftp://x", "file:///etc/passwd", "http://10.0.0.1/x"}
	for _, u := range ok {
		if err := checkURL(u); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := checkURL(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestStaleWarning(t *testing.T) {
	srv := newFeedServer(t)
	opts := srv.options(t, t.TempDir())
	if _, err := Update(ctx, opts, false); err != nil {
		t.Fatal(err)
	}
	var msgs []string
	later := Options{
		CacheDir: opts.CacheDir, Offline: true,
		Now:  func() time.Time { return time.Now().Add(5 * 24 * time.Hour) },
		Warn: func(s string) { msgs = append(msgs, s) },
	}
	if _, err := Open(ctx, later); err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Errorf("expected stale warnings for KEV and EPSS, got %v", msgs)
	}
}
