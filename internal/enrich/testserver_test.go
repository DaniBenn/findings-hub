package enrich

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// feedServer serves fixture feeds and counts requests, so tests never touch
// the real internet.
type feedServer struct {
	*httptest.Server
	kev, epss  []byte
	osv        map[string]string // id -> JSON body
	hits       map[string]*atomic.Int32
	kevETag    string
	failKEV    atomic.Bool
	corruptKEV atomic.Bool
	clock      atomic.Int64 // test time, unix nanoseconds
}

func newFeedServer(t *testing.T) *feedServer {
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

	fs := &feedServer{
		kev: kev, epss: gz.Bytes(), kevETag: `"kev-v1"`,
		osv: map[string]string{
			"GHSA-35jh-r3h4-6jhm": `{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"]}`,
		},
		hits: map[string]*atomic.Int32{"kev": {}, "epss": {}, "osv": {}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		fs.hits["kev"].Add(1)
		if r.Header.Get("User-Agent") == "" || !strings.HasPrefix(r.Header.Get("User-Agent"), "fhub/") {
			http.Error(w, "bad UA", http.StatusBadRequest)
			return
		}
		if fs.failKEV.Load() {
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		if fs.corruptKEV.Load() {
			w.Write([]byte(`{"vulnerabilities":[]}`))
			return
		}
		if r.Header.Get("If-None-Match") == fs.kevETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", fs.kevETag)
		w.Write(fs.kev)
	})
	mux.HandleFunc("/epss.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		fs.hits["epss"].Add(1)
		w.Write(fs.epss)
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		fs.hits["osv"].Add(1)
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		body, ok := fs.osv[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	})
	fs.Server = httptest.NewServer(mux)
	t.Cleanup(fs.Close)
	return fs
}

func (fs *feedServer) options(t *testing.T, dir string) Options {
	if fs.clock.Load() == 0 {
		fs.clock.Store(time.Now().Truncate(time.Second).UnixNano())
	}
	return Options{
		CacheDir: dir,
		Sources:  Sources{KEV: fs.URL + "/kev.json", EPSS: fs.URL + "/epss.csv.gz", OSV: fs.URL},
		Fetcher:  &Fetcher{Client: fs.Client(), UserAgent: "fhub/test"},
		Warn:     func(s string) { t.Log("warn:", s) },
		// A controlled clock: tests advance it explicitly instead of relying on
		// wall-clock ticks (Windows' clock is too coarse for that).
		Now: func() time.Time { return time.Unix(0, fs.clock.Load()) },
	}
}

// advance moves the test clock forward.
func (fs *feedServer) advance(d time.Duration) { fs.clock.Add(int64(d)) }
