package enrich

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheDir returns $FHUB_CACHE_DIR, or <user cache dir>/fhub.
func DefaultCacheDir() (string, error) {
	if d := os.Getenv("FHUB_CACHE_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating cache directory (set FHUB_CACHE_DIR): %w", err)
	}
	return filepath.Join(base, "fhub"), nil
}

// SourceMeta records what we know about one cached feed.
type SourceMeta struct {
	URL       string    `json:"url"`
	FetchedAt time.Time `json:"fetched_at"`
	ETag      string    `json:"etag,omitempty"`
	SHA256    string    `json:"sha256"`
	Bytes     int       `json:"bytes"`
	DataDate  string    `json:"data_date,omitempty"`
	Records   int       `json:"records"`
}

type cache struct{ dir string }

const metaFile = "meta.json"

func (c cache) path(name string) string { return filepath.Join(c.dir, name) }

func (c cache) readMeta() (map[string]SourceMeta, error) {
	m := map[string]SourceMeta{}
	b, err := os.ReadFile(c.path(metaFile))
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		// A corrupt meta file just means "nothing cached".
		return map[string]SourceMeta{}, nil
	}
	return m, nil
}

func (c cache) writeMeta(m map[string]SourceMeta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return c.writeAtomic(metaFile, b)
}

// writeAtomic writes via temp file + rename so readers never see half a file.
func (c cache) writeAtomic(name string, data []byte) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.dir, name+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path(name))
}

// readVerified reads a cached file and checks it against the recorded hash.
func (c cache) readVerified(name string, meta SourceMeta) ([]byte, error) {
	b, err := os.ReadFile(c.path(name))
	if err != nil {
		return nil, err
	}
	if sha(b) != meta.SHA256 {
		return nil, fmt.Errorf("cached %s failed integrity check (run `fhub db update --force`)", name)
	}
	return b, nil
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
