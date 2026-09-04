package refetch_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/refetch"
)

func TestFetch(t *testing.T) {
	body := []byte("%PDF-1.4 hello")
	hops := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "recheck") {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Write(body)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/a", http.StatusFound) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte("x"), refetch.MaxBytes+1)) })
	mux.HandleFunc("/exact", func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte("x"), refetch.MaxBytes)) })
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "gone", http.StatusNotFound) })
	mux.HandleFunc("/to-issuer", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://exhibitb.autofract.com/api/receipt/x", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := refetch.NewClient()
	ctx := context.Background()

	want := sha256.Sum256(body)
	res, err := refetch.Fetch(ctx, client, srv.URL+"/a")
	if err != nil || res.SHA256 != hex.EncodeToString(want[:]) || res.Status != 200 || res.Bytes != int64(len(body)) || res.ContentType != "application/pdf" || res.FinalURL != srv.URL+"/a" {
		t.Errorf("match: %+v %v", res, err)
	}
	res, err = refetch.Fetch(ctx, client, srv.URL+"/redirect")
	if err != nil || res.SHA256 != hex.EncodeToString(want[:]) || res.FinalURL != srv.URL+"/a" {
		t.Errorf("redirect: %+v %v", res, err)
	}
	if _, err := refetch.Fetch(ctx, client, srv.URL+"/loop"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("loop: %v", err)
	}
	if hops > refetch.MaxRedirects+1 {
		t.Errorf("followed %d hops", hops)
	}
	if _, err := refetch.Fetch(ctx, client, srv.URL+"/big"); !errors.Is(err, refetch.ErrTooLarge) {
		t.Errorf("big: %v", err)
	}
	if res, err := refetch.Fetch(ctx, client, srv.URL+"/exact"); err != nil || res.Bytes != refetch.MaxBytes {
		t.Errorf("exactly the cap: %+v %v", res, err)
	}
	if res, err := refetch.Fetch(ctx, client, srv.URL+"/gone"); err != nil || res.Status != 404 {
		t.Errorf("404 still hashes: %+v %v", res, err)
	}
	// A different body is a different hash: what "changed" is made of.
	other, _ := refetch.Fetch(ctx, client, srv.URL+"/gone")
	if other.SHA256 == res.SHA256 && other.SHA256 == hex.EncodeToString(want[:]) {
		t.Error("hashes should differ")
	}

	// Nothing answers here.
	dead := httptest.NewServer(mux)
	dead.Close()
	if _, err := refetch.Fetch(ctx, client, dead.URL+"/a"); err == nil {
		t.Error("unreachable server should error")
	}
}

func TestNeverContactsTheIssuer(t *testing.T) {
	for _, host := range []string{"exhibitb.autofract.com", "EXHIBITB.autofract.com", "exhibitb.com", "exhibitb", "exhibitb.autofract.com.", "exhibitb.autofract.com:443"} {
		if !refetch.IsIssuerHost(host) {
			t.Errorf("%s should be refused", host)
		}
	}
	for _, host := range []string{"example.org", "notexhibitb.com", "exhibitb-roots.example", "www.exhibitb.autofract.com.evil.example"} {
		if refetch.IsIssuerHost(host) {
			t.Errorf("%s should be allowed", host)
		}
	}
	client := refetch.NewClient()
	// Refused before any connection: a port nobody listens on never gets dialed.
	if _, err := refetch.Fetch(context.Background(), client, "https://exhibitb.autofract.com/api/receipt/eb_2m4Kq8Xr7vTb3nHd"); !errors.Is(err, refetch.ErrIssuerHost) {
		t.Errorf("issuer URL: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://exhibitb.autofract.com/", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := refetch.Fetch(context.Background(), client, srv.URL+"/"); !errors.Is(err, refetch.ErrIssuerHost) {
		t.Errorf("redirect to the issuer: %v", err)
	}
	for _, bad := range []string{"ftp://example.org/x", "file:///etc/passwd", "example.org/x", "http:///x"} {
		if _, err := refetch.Fetch(context.Background(), client, bad); err == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
}
