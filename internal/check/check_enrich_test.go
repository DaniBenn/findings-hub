package check

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/DaniBenn/findings-hub/internal/enrich"
	"github.com/DaniBenn/findings-hub/internal/model"
	"github.com/DaniBenn/findings-hub/internal/prioritize"
)

// fixtureEnricher serves testdata/intel through a local server, so the
// whole pipeline runs with "real" feeds and no internet.
func fixtureEnricher(t *testing.T) *enrich.Enricher {
	t.Helper()
	kev, err := os.ReadFile("../../testdata/intel/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	csv, err := os.ReadFile("../../testdata/intel/epss.csv")
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(csv)
	zw.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, _ *http.Request) { w.Write(kev) })
	mux.HandleFunc("/epss.csv.gz", func(w http.ResponseWriter, _ *http.Request) { w.Write(gz.Bytes()) })
	mux.HandleFunc("/v1/vulns/", http.NotFound)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	e, err := enrich.Open(context.Background(), enrich.Options{
		CacheDir: t.TempDir(),
		Sources:  enrich.Sources{KEV: srv.URL + "/kev.json", EPSS: srv.URL + "/epss.csv.gz", OSV: srv.URL},
		Fetcher:  &enrich.Fetcher{Client: srv.Client(), UserAgent: "fhub/test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEndToEndWithExploitIntel(t *testing.T) {
	rep, err := Run(context.Background(), Options{
		Inputs: allInputs, FailOn: []model.Priority{model.P0},
		Prioritize: prioritize.DefaultConfig(), Enricher: fixtureEnricher(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := rep.Summary
	// Log4Shell is in KEV, so it moves from P1 (critical) to P0.
	want := map[string]int{"P0": 2, "P1": 0, "P2": 3, "P3": 2, "P4": 1}
	for p, n := range want {
		if s.ByPriority[p] != n {
			t.Errorf("%s = %d, want %d (all: %v)", p, s.ByPriority[p], n, s.ByPriority)
		}
	}
	if s.Blocking != 2 || !s.Intel.Enabled || s.Intel.KEVVersion != "2026.11.09" || s.Intel.EPSSDate != "2026-11-09" {
		t.Errorf("summary = %+v", s)
	}

	var log4j, lodash *model.Finding
	for i := range rep.Findings {
		switch rep.Findings[i].VulnID {
		case "CVE-2021-44228":
			log4j = &rep.Findings[i]
		case "CVE-2021-23337":
			lodash = &rep.Findings[i]
		}
	}
	if log4j == nil || log4j.Priority != model.P0 || !strings.Contains(log4j.Reasons[0], "CISA KEV") ||
		!strings.Contains(log4j.Reasons[0], "ransomware") {
		t.Errorf("log4j = %+v", log4j)
	}
	if lodash == nil || lodash.Priority != model.P2 || lodash.EPSS == nil {
		t.Errorf("lodash = %+v", lodash)
	}
}
