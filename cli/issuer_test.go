package cli

import (
	"net/http"
	"strings"
	"testing"
)

// The issuer fetch must not follow a redirect that leaves the issuer's hosts: the receipt id
// would go to whoever the redirect names, and their answer is what would be verified.
func TestIssuerClientRefusesRedirectsOffTheIssuer(t *testing.T) {
	redirect := issuerClient().CheckRedirect
	if redirect == nil {
		t.Fatal("the issuer client follows redirects unchecked")
	}
	cases := []struct {
		url  string
		hops int
		want string
	}{
		{"https://exhibitb.autofract.com/api/receipt/eb_x", 1, ""},
		{"https://api.exhibitb.autofract.com/r/eb_x", 1, ""},
		{"https://evil.example/api/receipt/eb_x", 1, "off the issuer"},
		{"https://exhibitb-roots.example/api/receipt/eb_x", 1, "off the issuer"},
		{"http://exhibitb.autofract.com/api/receipt/eb_x", 1, "off the issuer"},
		{"https://exhibitb.autofract.com/api/receipt/eb_x", 5, "more than 5 redirects"},
	}
	for _, c := range cases {
		req, err := http.NewRequest(http.MethodGet, c.url, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		via := make([]*http.Request, c.hops)
		err = redirect(req, via)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s after %d hops: refused with %v, expected it to be followed", c.url, c.hops, err)
		case c.want != "" && err == nil:
			t.Errorf("%s after %d hops: followed, expected %q", c.url, c.hops, c.want)
		case c.want != "" && err != nil && !strings.Contains(err.Error(), c.want):
			t.Errorf("%s after %d hops: %v, expected %q", c.url, c.hops, err, c.want)
		}
	}
}
