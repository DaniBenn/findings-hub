package enrich

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Fetcher downloads intelligence feeds. It refuses plain HTTP except to
// loopback addresses (used by tests), caps response sizes, and identifies
// itself only by tool name and version.
type Fetcher struct {
	Client    *http.Client
	UserAgent string
}

// NewFetcher returns a Fetcher with sane timeouts.
func NewFetcher(version string) *Fetcher {
	return &Fetcher{
		Client:    &http.Client{Timeout: 90 * time.Second},
		UserAgent: "fhub/" + version,
	}
}

// errNotModified is returned by get when the server answered 304.
var errNotModified = errors.New("not modified")

type response struct {
	Body []byte
	ETag string
}

// get fetches rawURL, sending If-None-Match when etag is set. maxBytes caps
// the body size.
func (f *Fetcher) get(ctx context.Context, rawURL, etag string, maxBytes int64) (response, error) {
	if err := checkURL(rawURL); err != nil {
		return response{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	// Redirects must stay on HTTPS too.
	c := *client
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return checkURL(r.URL.String())
	}
	resp, err := c.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return response{ETag: etag}, errNotModified
	case resp.StatusCode == http.StatusNotFound:
		return response{}, errNotFound
	case resp.StatusCode != http.StatusOK:
		return response{}, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return response{}, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	if int64(len(body)) > maxBytes {
		return response{}, fmt.Errorf("GET %s: response larger than %d bytes", rawURL, maxBytes)
	}
	return response{Body: body, ETag: resp.Header.Get("ETag")}, nil
}

var errNotFound = errors.New("not found")

// checkURL allows https everywhere and http only for loopback hosts.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("refusing non-HTTPS URL %q", raw)
}
