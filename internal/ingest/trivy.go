package ingest

import (
	"encoding/json"

	"github.com/DaniBenn/findings-hub/internal/model"
)

// Subset of Trivy's JSON report (SchemaVersion 2) that we use.
type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	Trivy         struct {
		Version string `json:"Version"`
	} `json:"Trivy"`
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			PkgPath          string `json:"PkgPath"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			Title       string   `json:"Title"`
			Description string   `json:"Description"`
			Severity    string   `json:"Severity"`
			PrimaryURL  string   `json:"PrimaryURL"`
			VendorIDs   []string `json:"VendorIDs"`
			CVSS        map[string]struct {
				V3Score  float64 `json:"V3Score"`
				V40Score float64 `json:"V40Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
			Match     string `json:"Match"`
		} `json:"Secrets"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			AVDID         string `json:"AVDID"`
			Title         string `json:"Title"`
			Description   string `json:"Description"`
			Message       string `json:"Message"`
			Resolution    string `json:"Resolution"`
			Severity      string `json:"Severity"`
			PrimaryURL    string `json:"PrimaryURL"`
			Status        string `json:"Status"`
			CauseMetadata struct {
				Resource  string `json:"Resource"`
				StartLine int    `json:"StartLine"`
				EndLine   int    `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

func detectTrivy(top map[string]json.RawMessage) bool {
	return has(top, "SchemaVersion") && (has(top, "Results") || has(top, "ArtifactName"))
}

func parseTrivy(data []byte, origin string) ([]model.Finding, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	src := func(rule, sev string) model.Source {
		return model.Source{Scanner: "trivy", Version: rep.Trivy.Version, RuleID: rule, Severity: sev, File: origin}
	}

	var out []model.Finding
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			id := normVulnID(v.VulnerabilityID)
			var aliases []string
			for _, a := range v.VendorIDs {
				if isVulnID(a) {
					aliases = append(aliases, normVulnID(a))
				}
			}
			var cvss float64
			for _, c := range v.CVSS {
				cvss = max(cvss, c.V3Score, c.V40Score)
			}
			out = append(out, model.Finding{
				Kind:        model.KindVuln,
				Title:       firstNonEmpty(v.Title, id),
				Description: v.Description,
				VulnID:      id,
				Aliases:     aliases,
				Package: &model.Package{
					Ecosystem:    firstNonEmpty(ecosystemFromPURL(v.PkgIdentifier.PURL), res.Type),
					Name:         v.PkgName,
					Version:      v.InstalledVersion,
					PURL:         v.PkgIdentifier.PURL,
					FixedVersion: v.FixedVersion,
				},
				Location: &model.Location{
					Path:     normalizePath(firstNonEmpty(v.PkgPath, res.Target)),
					Artifact: rep.ArtifactName,
				},
				Severity: model.ParseSeverity(v.Severity),
				CVSS:     cvss,
				URL:      v.PrimaryURL,
				Sources:  []model.Source{src(id, v.Severity)},
			})
		}

		for _, s := range res.Secrets {
			// Trivy masks the secret in Match, but we hash it anyway and
			// never keep the text.
			out = append(out, model.Finding{
				Kind:      model.KindSecret,
				Title:     firstNonEmpty(s.Title, s.RuleID),
				RuleID:    s.RuleID,
				Location:  &model.Location{Path: normalizePath(res.Target), StartLine: s.StartLine, EndLine: s.EndLine, Artifact: rep.ArtifactName},
				Severity:  model.ParseSeverity(s.Severity),
				Sources:   []model.Source{src(s.RuleID, s.Severity)},
				MatchHash: model.HashContent(s.Match),
			})
		}

		for _, m := range res.Misconfigurations {
			if m.Status != "" && m.Status != "FAIL" {
				continue // PASS / EXCEPTION results are not findings
			}
			rule := firstNonEmpty(m.AVDID, m.ID)
			desc := firstNonEmpty(m.Message, m.Description)
			if m.Resolution != "" {
				desc += "\nResolution: " + m.Resolution
			}
			out = append(out, model.Finding{
				Kind:        model.KindIaC,
				Title:       firstNonEmpty(m.Title, rule),
				Description: desc,
				RuleID:      rule,
				Location: &model.Location{
					Path:      normalizePath(res.Target),
					StartLine: m.CauseMetadata.StartLine,
					EndLine:   m.CauseMetadata.EndLine,
					Artifact:  rep.ArtifactName,
				},
				Severity:  model.ParseSeverity(m.Severity),
				URL:       m.PrimaryURL,
				Sources:   []model.Source{src(rule, m.Severity)},
				MatchHash: model.HashContent(m.CauseMetadata.Resource),
			})
		}
	}
	return out, nil
}
