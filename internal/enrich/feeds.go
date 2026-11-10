package enrich

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// ---- CISA KEV --------------------------------------------------------------

type kevCatalog struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// parseKEV parses and validates the CISA KEV JSON feed.
func parseKEV(data []byte) (map[string]model.KEV, string, error) {
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, "", fmt.Errorf("KEV feed: %w", err)
	}
	if len(cat.Vulnerabilities) == 0 {
		return nil, "", errors.New("KEV feed: no vulnerabilities (refusing to use an empty catalog)")
	}
	out := make(map[string]model.KEV, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CveID))
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		out[id] = model.KEV{
			DateAdded:  v.DateAdded,
			DueDate:    v.DueDate,
			Ransomware: strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"),
		}
	}
	return out, firstNonEmpty(cat.CatalogVersion, cat.DateReleased), nil
}

// ---- FIRST EPSS ------------------------------------------------------------

// maxEPSSUncompressed caps decompression (the real file is ~10 MB).
const maxEPSSUncompressed = 256 << 20

// scanEPSS reads the gzipped EPSS CSV. For every row whose CVE is in want
// (or every row when want is nil) it calls fn. It returns the score date
// and the number of rows seen.
func scanEPSS(gz []byte, want map[string]bool, fn func(cve string, e model.EPSS)) (date string, rows int, err error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return "", 0, fmt.Errorf("EPSS feed: %w", err)
	}
	defer zr.Close()
	br := bufio.NewReader(io.LimitReader(zr, maxEPSSUncompressed))

	// Leading comment line: "#model_version:v2026.06.15,score_date:2026-11-09T12:00:23Z"
	for {
		b, err := br.Peek(1)
		if err != nil || b[0] != '#' {
			break
		}
		line, _ := br.ReadString('\n')
		for _, kv := range strings.Split(strings.TrimSpace(line[1:]), ",") {
			if k, v, ok := strings.Cut(kv, ":"); ok && k == "score_date" {
				date, _, _ = strings.Cut(v, "T")
			}
		}
	}

	r := csv.NewReader(br)
	r.ReuseRecord = true
	header, err := r.Read()
	if err != nil {
		return "", 0, fmt.Errorf("EPSS feed: reading header: %w", err)
	}
	if len(header) < 3 || header[0] != "cve" || header[1] != "epss" || header[2] != "percentile" {
		return "", 0, fmt.Errorf("EPSS feed: unexpected header %v", header)
	}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", rows, fmt.Errorf("EPSS feed: line %d: %w", rows+2, err)
		}
		rows++
		cve := rec[0]
		if want != nil && !want[cve] {
			continue
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 != nil || err2 != nil || score < 0 || score > 1 {
			continue
		}
		fn(cve, model.EPSS{Score: score, Percentile: pct, Date: date})
	}
	if rows == 0 {
		return "", 0, errors.New("EPSS feed: no rows (refusing to use an empty feed)")
	}
	return date, rows, nil
}

// ---- OSV -------------------------------------------------------------------

type osvVuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

func parseOSV(data []byte) ([]string, error) {
	var v osvVuln
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("OSV response: %w", err)
	}
	return v.Aliases, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
