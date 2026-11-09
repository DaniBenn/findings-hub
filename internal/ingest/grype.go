package ingest

import (
	"encoding/json"

	"github.com/DaniBenn/findings-hub/internal/model"
)

type grypeCVSS struct {
	Version string `json:"version"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

// Subset of Grype's JSON output (`grype -o json`) that we use.
type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string      `json:"id"`
			DataSource  string      `json:"dataSource"`
			Severity    string      `json:"severity"`
			Description string      `json:"description"`
			CVSS        []grypeCVSS `json:"cvss"`
			Fix         struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID          string      `json:"id"`
			Description string      `json:"description"`
			CVSS        []grypeCVSS `json:"cvss"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			PURL      string `json:"purl"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
	Source struct {
		Type   string          `json:"type"`
		Target json.RawMessage `json:"target"`
	} `json:"source"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

func detectGrype(top map[string]json.RawMessage) bool {
	return has(top, "matches") && (has(top, "descriptor") || has(top, "source"))
}

func parseGrype(data []byte, origin string) ([]model.Finding, error) {
	var rep grypeReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	artifact := grypeTarget(rep.Source.Target)

	out := make([]model.Finding, 0, len(rep.Matches))
	for _, m := range rep.Matches {
		v := m.Vulnerability
		id := normVulnID(v.ID)

		cvss := maxCVSS(v.CVSS)
		desc := v.Description
		var aliases []string
		for _, r := range m.RelatedVulnerabilities {
			if rid := normVulnID(r.ID); rid != id && isVulnID(rid) {
				aliases = append(aliases, rid)
			}
			cvss = max(cvss, maxCVSS(r.CVSS))
			desc = firstNonEmpty(desc, r.Description)
		}

		var fixed string
		if v.Fix.State == "fixed" && len(v.Fix.Versions) > 0 {
			fixed = v.Fix.Versions[0]
		}
		var loc string
		if len(m.Artifact.Locations) > 0 {
			loc = m.Artifact.Locations[0].Path
		}

		out = append(out, model.Finding{
			Kind:        model.KindVuln,
			Title:       id,
			Description: desc,
			VulnID:      id,
			Aliases:     aliases,
			Package: &model.Package{
				Ecosystem:    firstNonEmpty(ecosystemFromPURL(m.Artifact.PURL), m.Artifact.Type),
				Name:         m.Artifact.Name,
				Version:      m.Artifact.Version,
				PURL:         m.Artifact.PURL,
				FixedVersion: fixed,
			},
			Location: &model.Location{Path: normalizePath(loc), Artifact: artifact},
			Severity: model.ParseSeverity(v.Severity),
			CVSS:     cvss,
			URL:      v.DataSource,
			Sources: []model.Source{{
				Scanner: firstNonEmpty(rep.Descriptor.Name, "grype"), Version: rep.Descriptor.Version,
				RuleID: id, Severity: v.Severity, File: origin,
			}},
		})
	}
	return out, nil
}

func maxCVSS(cs []grypeCVSS) float64 {
	var m float64
	for _, c := range cs {
		m = max(m, c.Metrics.BaseScore)
	}
	return m
}

// grypeTarget extracts a display name from source.target, which is a string
// for directories and an object (with userInput) for images.
func grypeTarget(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		UserInput string `json:"userInput"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.UserInput
	}
	return ""
}
