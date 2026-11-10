package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// glob matches forward-slash paths. "*" matches within one path segment,
// "**" matches across segments, "?" matches one character.
type glob struct{ re *regexp.Regexp }

func compileGlob(pattern string) (*glob, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	p := strings.TrimPrefix(strings.ReplaceAll(pattern, `\`, "/"), "./")
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '*' && i+1 < len(p) && p[i+1] == '*':
			i++
			if i+1 < len(p) && p[i+1] == '/' {
				i++
				b.WriteString("(?:.*/)?") // "**/" = zero or more directories
			} else {
				b.WriteString(".*")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	return &glob{re}, nil
}

func (g *glob) match(path string) bool {
	return g.re.MatchString(strings.TrimPrefix(path, "/"))
}
