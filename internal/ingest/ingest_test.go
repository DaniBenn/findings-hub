package ingest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/DaniBenn/findings-hub/internal/model"
)

const td = "../../testdata/"

func TestDetectAndParse(t *testing.T) {
	tests := []struct {
		file   string
		format string
		count  int
	}{
		{"trivy-fs.json", "trivy", 5}, // 3 vulns + 1 secret + 1 FAIL misconfig (PASS skipped)
		{"grype-dir.json", "grype", 3},
		{"semgrep.sarif", "sarif", 2},
		{"gitleaks.sarif", "sarif", 1},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			res, err := File(td + tt.file)
			if err != nil {
				t.Fatal(err)
			}
			if res.Format != tt.format {
				t.Errorf("format = %q, want %q", res.Format, tt.format)
			}
			if len(res.Findings) != tt.count {
				t.Errorf("got %d findings, want %d", len(res.Findings), tt.count)
			}
			for _, f := range res.Findings {
				if len(f.Sources) != 1 || f.Sources[0].Scanner == "" {
					t.Errorf("finding %q has bad sources: %+v", f.Title, f.Sources)
				}
			}
		})
	}
}

func TestTrivyFields(t *testing.T) {
	res, err := File(td + "trivy-fs.json")
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, res.Findings, func(f model.Finding) bool { return f.VulnID == "CVE-2021-44228" })
	if f.Severity != model.SeverityCritical || f.CVSS != 10 {
		t.Errorf("severity/cvss = %v/%v", f.Severity, f.CVSS)
	}
	if f.Package.Ecosystem != "maven" || f.Package.FixedVersion != "2.15.0" || f.Location.Path != "pom.xml" {
		t.Errorf("package/location wrong: %+v %+v", f.Package, f.Location)
	}
	iac := find(t, res.Findings, func(f model.Finding) bool { return f.Kind == model.KindIaC })
	if iac.RuleID != "AVD-DS-0002" || iac.Severity != model.SeverityHigh {
		t.Errorf("iac = %+v", iac)
	}
}

func TestGrypeAliases(t *testing.T) {
	res, err := File(td + "grype-dir.json")
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, res.Findings, func(f model.Finding) bool { return f.VulnID == "GHSA-35jh-r3h4-6jhm" })
	if len(f.Aliases) != 1 || f.Aliases[0] != "CVE-2021-23337" {
		t.Errorf("aliases = %v", f.Aliases)
	}
	semver := find(t, res.Findings, func(f model.Finding) bool { return f.Package.Name == "semver" })
	if semver.Package.FixedVersion != "" {
		t.Errorf("not-fixed vuln should have no fixed version, got %q", semver.Package.FixedVersion)
	}
}

func TestSARIFSeverityAndKind(t *testing.T) {
	res, err := File(td + "semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}
	sqli := find(t, res.Findings, func(f model.Finding) bool { return strings.Contains(f.RuleID, "sqli") })
	// security-severity 8.1 must beat level "warning".
	if sqli.Severity != model.SeverityHigh || sqli.Kind != model.KindCode {
		t.Errorf("sqli severity/kind = %v/%v", sqli.Severity, sqli.Kind)
	}
	if sqli.Location.Path != "src/main/java/com/demo/UserRepo.java" || sqli.Location.StartLine != 42 {
		t.Errorf("location = %+v", sqli.Location)
	}
	weak := find(t, res.Findings, func(f model.Finding) bool { return strings.Contains(f.RuleID, "weak-random") })
	if weak.Severity != model.SeverityLow {
		t.Errorf("weak-random severity = %v, want low (from rule default level note)", weak.Severity)
	}
	if weak.Location.Path != "src/main/java/com/demo/Token.java" {
		t.Errorf("leading ./ not stripped: %q", weak.Location.Path)
	}
}

// Security property: raw secret values must never appear in our output.
func TestSecretValueNeverStored(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	res, err := File(td + "gitleaks.sarif")
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if f.Kind != model.KindSecret {
		t.Fatalf("kind = %v, want secret", f.Kind)
	}
	if f.MatchHash == "" {
		t.Error("secret finding should carry a match hash for fingerprinting")
	}
	out, _ := json.Marshal(res.Findings)
	if strings.Contains(string(out), secret) || strings.Contains(f.MatchHash, secret) {
		t.Fatal("raw secret leaked into findings")
	}
}

func TestUnknownFormat(t *testing.T) {
	_, err := Bytes([]byte(`{"hello":"world"}`), "x.json")
	if !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("err = %v, want ErrUnknownFormat", err)
	}
	if _, err := Bytes([]byte(`not json`), "x"); err == nil {
		t.Fatal("expected error for non-JSON input")
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"./src/a.go":               "src/a.go",
		`src\win\a.go`:             "src/win/a.go",
		"file:///home/u/repo/a.go": "/home/u/repo/a.go",
		"file:///C:/repo/a.go":     "C:/repo/a.go",
		"src/with%20space.go":      "src/with space.go",
		"":                         "",
		"/package-lock.json":       "/package-lock.json",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func find(t *testing.T, fs []model.Finding, pred func(model.Finding) bool) model.Finding {
	t.Helper()
	for _, f := range fs {
		if pred(f) {
			return f
		}
	}
	t.Fatal("finding not found")
	return model.Finding{}
}
