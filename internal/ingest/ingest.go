// Package ingest detects scanner output formats and converts them into
// normalized model.Findings.
package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// MaxInputBytes caps a single input file to protect against runaway memory use.
const MaxInputBytes = 512 << 20 // 512 MiB

// ErrUnknownFormat is returned when no parser recognizes the input.
var ErrUnknownFormat = errors.New("unrecognized scanner output format")

// parser converts one scanner format.
type parser struct {
	name   string
	detect func(top map[string]json.RawMessage) bool
	parse  func(data []byte, origin string) ([]model.Finding, error)
}

// Order matters: the most specific detectors go first.
var parsers = []parser{
	{name: "sarif", detect: detectSARIF, parse: parseSARIF},
	{name: "trivy", detect: detectTrivy, parse: parseTrivy},
	{name: "grype", detect: detectGrype, parse: parseGrype},
}

// Result is the outcome of ingesting one input.
type Result struct {
	Origin   string
	Format   string
	Findings []model.Finding
}

// File ingests one file. Use "-" for stdin.
func File(path string) (Result, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return Result{}, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxInputBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > MaxInputBytes {
		return Result{}, fmt.Errorf("%s: input larger than %d bytes", path, MaxInputBytes)
	}
	return Bytes(data, path)
}

// Bytes ingests already-loaded data. origin is used for error messages and
// recorded on each finding's Source.
func Bytes(data []byte, origin string) (Result, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return Result{}, fmt.Errorf("%s: not a JSON object: %w", origin, err)
	}
	for _, p := range parsers {
		if !p.detect(top) {
			continue
		}
		fs, err := p.parse(data, origin)
		if err != nil {
			return Result{}, fmt.Errorf("%s: parsing as %s: %w", origin, p.name, err)
		}
		return Result{Origin: origin, Format: p.name, Findings: fs}, nil
	}
	return Result{}, fmt.Errorf("%s: %w (supported: SARIF 2.1.0, Trivy JSON, Grype JSON)", origin, ErrUnknownFormat)
}

func has(top map[string]json.RawMessage, keys ...string) bool {
	for _, k := range keys {
		if _, ok := top[k]; !ok {
			return false
		}
	}
	return true
}
