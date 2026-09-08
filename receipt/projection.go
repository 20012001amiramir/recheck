package receipt

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/internal/schema"
)

// Two-label suffixes that are registries rather than registrable names (§11).
var multiLabelSuffixes = map[string]bool{
	"ac.jp": true, "ac.uk": true, "co.in": true, "co.jp": true, "co.nz": true, "co.uk": true,
	"co.za": true, "com.au": true, "com.br": true, "edu.au": true, "gov.au": true, "gov.uk": true,
	"net.au": true, "org.au": true, "org.uk": true,
}

var reIPv4 = regexp.MustCompile(`\A[0-9]{1,3}(\.[0-9]{1,3}){3}\z`)

// RegistrableHost is the host a projection shows for a URL (§11): lowercased, `www.` dropped,
// cut to the last two labels (three under a registry suffix); an IPv4 literal kept whole. Empty
// when the URL does not parse or the host is not a plain domain name (an IPv6 literal, an empty
// label), so a projection always passes its own schema.
func RegistrableHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "www.")
	if host == "" || strings.HasPrefix(host, "[") || strings.Contains(host, ":") {
		return ""
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if l == "" {
			return ""
		}
	}
	result := host
	if !reIPv4.MatchString(host) && len(labels) > 2 {
		n := 2
		if multiLabelSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
			n = 3
		}
		result = strings.Join(labels[len(labels)-n:], ".")
	}
	if schema.Domain(result) != "" {
		return ""
	}
	return result
}

// Domain is what a claim's locator shows in public: the registrable host of the final URL (else
// of the cited URL) for a url locator, the registry agency for doi/pmid/case, nothing for an
// unsupported one. Empty means null.
func Domain(c *Claim) string {
	switch c.Locator.Type {
	case "unsupported":
		return ""
	case "url":
		if c.Exists.FinalURL != nil {
			return RegistrableHost(*c.Exists.FinalURL)
		}
		return RegistrableHost(c.Locator.Value)
	default:
		if c.Exists.Registry != nil {
			return c.Exists.Registry.Agency
		}
		return ""
	}
}

// Project builds the public projection (§11) of a parsed receipt as a JSON value: every member
// of the source in its original order, with each locator reduced to {type, domain}, each exists
// losing final_url and archive_url, and its registry losing cluster_id — a registry's public
// identifier of a record names the cited work as surely as the citation does. A projection
// projects to itself.
func Project(r *Receipt, raw *canonical.Value) (*canonical.Value, error) {
	if r == nil || raw == nil || raw.Kind != canonical.Object {
		return nil, errors.New("project: need a validated receipt")
	}
	out := &canonical.Value{Kind: canonical.Object}
	for _, m := range raw.Members {
		if m.Key != "claims" || r.Projected {
			out.Members = append(out.Members, m)
			continue
		}
		claims := &canonical.Value{Kind: canonical.Array}
		for i, c := range m.Value.Array {
			claims.Array = append(claims.Array, projectClaim(&r.Claims[i], c))
		}
		out.Members = append(out.Members, canonical.Member{Key: m.Key, Value: claims})
	}
	return out, nil
}

// projectRegistry is the registry member without cluster_id, every other member in its order.
func projectRegistry(raw *canonical.Value) *canonical.Value {
	out := &canonical.Value{Kind: canonical.Object}
	for _, m := range raw.Members {
		if m.Key == "cluster_id" {
			continue
		}
		out.Members = append(out.Members, m)
	}
	return out
}

func projectClaim(c *Claim, raw *canonical.Value) *canonical.Value {
	out := &canonical.Value{Kind: canonical.Object}
	for _, m := range raw.Members {
		switch m.Key {
		case "locator":
			loc := &canonical.Value{Kind: canonical.Object}
			loc.Members = append(loc.Members, canonical.Member{Key: "type", Value: &canonical.Value{Kind: canonical.String, Str: c.Locator.Type}})
			dom := &canonical.Value{Kind: canonical.Null}
			if d := Domain(c); d != "" {
				dom = &canonical.Value{Kind: canonical.String, Str: d}
			}
			loc.Members = append(loc.Members, canonical.Member{Key: "domain", Value: dom})
			out.Members = append(out.Members, canonical.Member{Key: "locator", Value: loc})
		case "exists":
			ex := &canonical.Value{Kind: canonical.Object}
			for _, em := range m.Value.Members {
				if em.Key == "final_url" || em.Key == "archive_url" {
					continue
				}
				if em.Key == "registry" && em.Value.Kind == canonical.Object {
					em = canonical.Member{Key: em.Key, Value: projectRegistry(em.Value)}
				}
				ex.Members = append(ex.Members, em)
			}
			out.Members = append(out.Members, canonical.Member{Key: "exists", Value: ex})
		default:
			out.Members = append(out.Members, m)
		}
	}
	return out
}
