package ingest

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// Subset of SARIF 2.1.0 that we use.
type sarifLog struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver     sarifComponent   `json:"driver"`
			Extensions []sarifComponent `json:"extensions"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	} `json:"runs"`
}

type sarifComponent struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	SemanticVer    string      `json:"semanticVersion"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifRule struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	ShortDescription     sarifText `json:"shortDescription"`
	FullDescription      sarifText `json:"fullDescription"`
	HelpURI              string    `json:"helpUri"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties sarifProps `json:"properties"`
}

type sarifProps struct {
	Tags             []string        `json:"tags"`
	SecuritySeverity json.RawMessage `json:"security-severity"`
}

type sarifResult struct {
	RuleID    string    `json:"ruleId"`
	RuleIndex *int      `json:"ruleIndex"`
	Level     string    `json:"level"`
	Message   sarifText `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int       `json:"startLine"`
				EndLine   int       `json:"endLine"`
				Snippet   sarifText `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          sarifProps        `json:"properties"`
}

func detectSARIF(top map[string]json.RawMessage) bool {
	if !has(top, "runs") {
		return false
	}
	var v, schema string
	_ = json.Unmarshal(top["version"], &v)
	_ = json.Unmarshal(top["$schema"], &schema)
	return strings.HasPrefix(v, "2.1") || strings.Contains(strings.ToLower(schema), "sarif")
}

func parseSARIF(data []byte, origin string) ([]model.Finding, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, run := range log.Runs {
		drv := run.Tool.Driver
		tool := scannerName(firstNonEmpty(drv.Name, "sarif"))
		toolVer := firstNonEmpty(drv.SemanticVer, drv.Version)

		byID := map[string]*sarifRule{}
		for _, comp := range append([]sarifComponent{drv}, run.Tool.Extensions...) {
			for i := range comp.Rules {
				if _, dup := byID[comp.Rules[i].ID]; !dup {
					byID[comp.Rules[i].ID] = &comp.Rules[i]
				}
			}
		}

		for _, r := range run.Results {
			rule := lookupRule(drv.Rules, byID, r)
			ruleID := r.RuleID
			if ruleID == "" && rule != nil {
				ruleID = rule.ID
			}

			kind := sarifKind(tool, ruleID, rule)
			sev, rawSev := sarifSeverity(r, rule)

			f := model.Finding{
				Kind:     kind,
				RuleID:   ruleID,
				Severity: sev,
				Sources: []model.Source{{
					Scanner: tool, Version: toolVer,
					RuleID: ruleID, Severity: rawSev, File: origin,
				}},
			}
			if rule != nil {
				f.URL = rule.HelpURI
				f.Title = firstNonEmpty(rule.ShortDescription.Text, rule.Name)
			}

			var snippet string
			if len(r.Locations) > 0 {
				pl := r.Locations[0].PhysicalLocation
				f.Location = &model.Location{
					Path:      normalizePath(pl.ArtifactLocation.URI),
					StartLine: pl.Region.StartLine,
					EndLine:   pl.Region.EndLine,
				}
				snippet = pl.Region.Snippet.Text
			}

			if kind == model.KindSecret {
				// Secret scanners may put the secret in the snippet or message:
				// keep only a hash, never the text.
				f.Title = firstNonEmpty(f.Title, ruleID, "Hard-coded secret")
				f.MatchHash = model.HashContent(snippet)
			} else {
				f.Title = firstNonEmpty(f.Title, firstLine(r.Message.Text), ruleID)
				f.Description = r.Message.Text
				f.MatchHash = model.HashContent(snippet)
				if f.MatchHash == "" {
					f.MatchHash = model.HashContent(r.PartialFingerprints["primaryLocationLineHash"])
				}
			}
			if kind == model.KindVuln {
				f.VulnID = normVulnID(ruleID)
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func lookupRule(driverRules []sarifRule, byID map[string]*sarifRule, r sarifResult) *sarifRule {
	if r.RuleIndex != nil && *r.RuleIndex >= 0 && *r.RuleIndex < len(driverRules) {
		if rr := &driverRules[*r.RuleIndex]; r.RuleID == "" || rr.ID == r.RuleID {
			return rr
		}
	}
	return byID[r.RuleID]
}

var (
	secretTools = []string{"gitleaks", "trufflehog", "detect-secrets", "ggshield", "secret"}
	iacTools    = []string{"checkov", "tfsec", "kics", "terrascan", "hadolint", "kube-linter", "kubesec", "trivy"}
)

// sarifKind classifies a SARIF result. Rule tags win, then rule ID shape,
// then the tool name.
func sarifKind(tool, ruleID string, rule *sarifRule) model.Kind {
	if rule != nil {
		for _, t := range rule.Properties.Tags {
			switch strings.ToLower(t) {
			case "secret", "secrets":
				return model.KindSecret
			case "iac", "misconfiguration", "terraform", "kubernetes", "dockerfile", "cloudformation":
				return model.KindIaC
			}
		}
	}
	if isVulnID(ruleID) {
		return model.KindVuln
	}
	lt := strings.ToLower(tool)
	for _, s := range secretTools {
		if strings.Contains(lt, s) {
			return model.KindSecret
		}
	}
	for _, s := range iacTools {
		if strings.Contains(lt, s) {
			return model.KindIaC
		}
	}
	return model.KindCode
}

// sarifSeverity prefers the numeric "security-severity" property (the
// convention GitHub code scanning uses), falling back to the SARIF level.
func sarifSeverity(r sarifResult, rule *sarifRule) (model.Severity, string) {
	raws := []json.RawMessage{r.Properties.SecuritySeverity}
	if rule != nil {
		raws = append(raws, rule.Properties.SecuritySeverity)
	}
	for _, raw := range raws {
		if score, ok := parseScore(raw); ok {
			return model.SeverityFromCVSS(score), strconv.FormatFloat(score, 'f', -1, 64)
		}
	}
	level := r.Level
	if level == "" && rule != nil {
		level = rule.DefaultConfiguration.Level
	}
	if level == "" {
		level = "warning" // SARIF default
	}
	return model.ParseSeverity(level), level
}

// parseScore accepts the score as a JSON string ("7.5") or number (7.5).
func parseScore(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, err == nil
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return f, true
	}
	return 0, false
}

// scannerName turns a SARIF driver name like "Semgrep OSS" into a short,
// stable identifier ("semgrep").
func scannerName(driver string) string {
	fields := strings.Fields(strings.ToLower(driver))
	if len(fields) == 0 {
		return "sarif"
	}
	return fields[0]
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}
