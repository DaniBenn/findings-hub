package ingest

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// normalizePath turns scanner-reported paths/URIs into clean, forward-slash,
// repo-relative-looking paths so the same file matches across scanners.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "file://") {
		if u, err := url.Parse(p); err == nil {
			p = u.Path
		}
	} else if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	p = strings.ReplaceAll(p, `\`, "/")
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "./")
	// Windows drive letters from file URIs: "/C:/x" -> "C:/x"
	if len(p) > 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	if p == "." {
		return ""
	}
	return p
}

// ecosystemFromPURL returns the purl type ("npm", "maven", "apk", ...).
func ecosystemFromPURL(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	typ, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(typ)
}

var (
	reCVE  = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)
	reGHSA = regexp.MustCompile(`(?i)^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
)

// isVulnID reports whether id looks like a public vulnerability identifier.
func isVulnID(id string) bool {
	return reCVE.MatchString(id) || reGHSA.MatchString(id)
}

// normVulnID uppercases the prefix of a vulnerability ID. GHSA IDs are
// lowercase after the prefix by convention.
func normVulnID(id string) string {
	id = strings.TrimSpace(id)
	switch {
	case reCVE.MatchString(id):
		return strings.ToUpper(id)
	case reGHSA.MatchString(id):
		return "GHSA" + strings.ToLower(id[4:])
	default:
		return id
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
