// Package refetch downloads a cited URL from the user's own machine and hashes the raw bytes, so a
// reader can see whether a source still carries what the receipt says it carried. It never
// contacts the issuer: any host named exhibitb or under exhibitb.* is refused before a connection
// is made, on the first request and on every redirect.
package refetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Limits of one fetch.
const (
	MaxBytes     = 5 << 20
	Timeout      = 15 * time.Second
	MaxRedirects = 5
)

// UserAgent is sent with every request. The CLI sets its version into it.
var UserAgent = "recheck (+https://github.com/20012001amiramir/recheck)"

// ErrIssuerHost is returned for a URL that would contact the issuer.
var ErrIssuerHost = errors.New("refusing to contact the issuer: refetch never goes through EXHIBIT B")

// ErrTooLarge is returned when the body exceeds MaxBytes; nothing is hashed.
var ErrTooLarge = fmt.Errorf("response larger than %d MB, not hashed", MaxBytes>>20)

// Result is one fetched URL.
type Result struct {
	URL         string `json:"url"`
	FinalURL    string `json:"final_url"`
	Status      int    `json:"status"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
}

// IsIssuerHost reports whether host is the issuer's: exhibitb or exhibitb.<anything>.
func IsIssuerHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	return h == "exhibitb" || strings.HasPrefix(h, "exhibitb.")
}

func check(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("URL has no host")
	}
	if IsIssuerHost(u.Hostname()) {
		return ErrIssuerHost
	}
	return nil
}

// NewClient is an http.Client with the package's timeout, redirect cap and issuer guard.
func NewClient() *http.Client {
	return &http.Client{
		Timeout: Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return fmt.Errorf("more than %d redirects", MaxRedirects)
			}
			return check(req.URL)
		},
	}
}

// Fetch downloads rawURL with client and hashes the raw body.
func Fetch(ctx context.Context, client *http.Client, rawURL string) (Result, error) {
	res := Result{URL: rawURL}
	u, err := url.Parse(rawURL)
	if err != nil {
		return res, err
	}
	if err := check(u); err != nil {
		return res, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	for k, v := range transportHeaders {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	res.FinalURL = resp.Request.URL.String()
	res.ContentType = resp.Header.Get("Content-Type")

	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return res, err
	}
	if n > MaxBytes {
		return res, ErrTooLarge
	}
	res.Bytes = n
	res.SHA256 = hex.EncodeToString(h.Sum(nil))
	return res, nil
}

// Hash fetches rawURL with a fresh client.
func Hash(rawURL string) (Result, error) {
	return Fetch(context.Background(), NewClient(), rawURL)
}
