package receipt

import (
	"strconv"

	"github.com/20012001amiramir/recheck/canonical"
	"github.com/20012001amiramir/recheck/internal/schema"
)

// SchemaError names the first member that does not match §4 (or §11), in the spec's path
// notation: $.claims[0].says.overlap_bp.
type SchemaError = schema.Error

const (
	maxClaims     = 1000
	maxModels     = 16
	maxRetrievers = 8
	maxBP         = 10000
	maxStatus     = 599
)

// Parse reads one JSON document and validates it as a receipt (§4) first and, failing that, as a
// public projection (§11). The returned error is a *canonical.Error when the text is not JSON
// and a *SchemaError when it is JSON of the wrong shape.
func Parse(data []byte) (*Receipt, *canonical.Value, error) {
	raw, err := canonical.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	r, err := FromValue(raw)
	return r, raw, err
}

// FromValue validates a parsed JSON value as a receipt, then as a projection.
func FromValue(raw *canonical.Value) (*Receipt, error) {
	r, receiptErr := validate(raw, false)
	if receiptErr == nil {
		return r, nil
	}
	p, projErr := validate(raw, true)
	if projErr == nil {
		return p, nil
	}
	if looksProjected(raw) {
		return nil, projErr
	}
	return nil, receiptErr
}

// looksProjected reports whether the first claim carries a projected locator, so the error a
// reader sees is the one about the shape they actually sent.
func looksProjected(raw *canonical.Value) bool {
	claims := raw.Get("claims")
	if claims == nil || claims.Kind != canonical.Array || len(claims.Array) == 0 {
		return false
	}
	loc := claims.Array[0].Get("locator")
	return loc != nil && loc.Get("domain") != nil && loc.Get("value") == nil
}

// DateShape reports whether s is a date (YYYY-MM-DD).
func DateShape(s string) bool { return schema.Date(s) == "" }

// KeyIDShape reports whether s is a key id (§4.1).
func KeyIDShape(s string) bool { return schema.KeyID(s) == "" }

// Hex64Shape reports whether s is hex64.
func Hex64Shape(s string) bool { return schema.Hex64(s) == "" }

// ReceiptIDShape reports whether s is a receipt id (eb_ plus 16 characters).
func ReceiptIDShape(s string) bool { return schema.ReceiptID(s) == "" }

// legacyFormat reports whether raw's engine.version is below 0.2.0, the version the format was
// finalized at. Such a body was sealed while the format was still being finalized and may omit
// claims[].source_of, counts.not_checked and registry.method (spec §15), read as "body", 0 and
// "lookup"; from 0.2.0 on all three are required. Read off the raw value before validation, so the
// rule can shape it; a version that is not a semver counts as current, and the shape rule then
// refuses it in its turn.
func legacyFormat(raw *canonical.Value) bool {
	ver := raw.Get("engine").Get("version")
	return ver != nil && ver.Kind == canonical.String && schema.SemverBefore(ver.Str, 0, 2, 0)
}

func validate(raw *canonical.Value, projected bool) (*Receipt, *SchemaError) {
	v := &schema.Validator{}
	r := &Receipt{Projected: projected}
	legacy := legacyFormat(raw)
	o := v.Object("$", raw)
	r.V = o.LiteralInt("v", 1)
	r.Kind = o.Enum("kind", KindChained, KindUnchained)
	r.ID = o.Str("id", schema.ReceiptID)
	r.Seq = o.IntOrNull("seq", 1, canonical.MaxSafeInteger)
	r.PrevHash = o.StrOrNull("prev_hash", schema.Hex64)
	r.IssuedAt = o.Str("issued_at", schema.Timestamp)

	iss := o.Obj("issuer")
	r.Issuer.Name = iss.Literal("name", IssuerName)
	r.Issuer.URL = iss.Str("url", schema.HTTPURL)
	r.Issuer.KeyID = iss.Str("key_id", schema.KeyID)
	r.Issuer.PublicKey = iss.Str("public_key", schema.PubKey)
	iss.Done()

	r.ScopeDisclaimer = o.Literal("scope_disclaimer", ScopeDisclaimer)

	doc := o.Obj("document")
	r.Document.SHA256 = doc.Str("sha256", schema.Hex64)
	r.Document.Bytes = doc.Int("bytes", 0, canonical.MaxSafeInteger)
	r.Document.MediaType = doc.Str("media_type", schema.MediaType)
	r.Document.TextSHA256 = doc.Str("text_sha256", schema.Hex64)
	r.Document.Chars = doc.Int("chars", 0, canonical.MaxSafeInteger)
	r.Document.Extractor = doc.Str("extractor", schema.Extractor)
	doc.Done()

	bnd := o.Obj("binding")
	r.Binding.Alg = bnd.Literal("alg", "HMAC-SHA256")
	r.Binding.KeySHA256 = bnd.Str("key_sha256", schema.Hex64)
	bnd.Done()

	claimsPath, claims := o.Array("claims", maxClaims)
	for i, c := range claims {
		r.Claims = append(r.Claims, validateClaim(v, claimsPath+"["+strconv.Itoa(i)+"]", c, projected, legacy))
	}

	cnt := o.Obj("counts")
	r.Counts.Claims = cnt.Int("claims", 0, canonical.MaxSafeInteger)
	if legacy {
		r.Counts.NotChecked = cnt.IntOr("not_checked", 0, 0, canonical.MaxSafeInteger)
	} else {
		r.Counts.NotChecked = cnt.Int("not_checked", 0, canonical.MaxSafeInteger)
	}
	r.Counts.Resolved = cnt.Int("resolved", 0, canonical.MaxSafeInteger)
	r.Counts.NoAccess = cnt.Int("no_access", 0, canonical.MaxSafeInteger)
	r.Counts.NotFound = cnt.Int("not_found", 0, canonical.MaxSafeInteger)
	r.Counts.Unreachable = cnt.Int("unreachable", 0, canonical.MaxSafeInteger)
	r.Counts.Unsupported = cnt.Int("unsupported", 0, canonical.MaxSafeInteger)
	r.Counts.SaysMatch = cnt.Int("says_match", 0, canonical.MaxSafeInteger)
	r.Counts.SaysDrift = cnt.Int("says_drift", 0, canonical.MaxSafeInteger)
	r.Counts.SaysNotFound = cnt.Int("says_not_found", 0, canonical.MaxSafeInteger)
	r.Counts.SaysNotRun = cnt.Int("says_not_run", 0, canonical.MaxSafeInteger)
	r.Counts.HoldsAttempted = cnt.Int("holds_attempted", 0, canonical.MaxSafeInteger)
	cnt.Done()

	modelsPath, models := o.Array("models", maxModels)
	for i, m := range models {
		mo := v.Object(modelsPath+"["+strconv.Itoa(i)+"]", m)
		r.Models = append(r.Models, Model{Role: mo.Str("role", schema.Token(24)), Model: mo.Str("model", schema.ModelID)})
		mo.Done()
	}

	eng := o.Obj("engine")
	r.Engine.Name = eng.Literal("name", "exhibitb")
	r.Engine.Version = eng.Str("version", schema.Semver)
	r.Engine.Normalize = eng.Literal("normalize", "norm@1")
	th := eng.Obj("says_thresholds")
	r.Engine.MatchBP = th.Int("match_bp", 0, maxBP)
	r.Engine.DriftMinBP = th.Int("drift_min_bp", 0, maxBP)
	th.Done()
	eng.Done()

	r.SelfHash = o.Str("self_hash", schema.Hex64)

	sigsPath, sigs := o.Array("signatures", MaxSignatures)
	for i, s := range sigs {
		so := v.Object(sigsPath+"["+strconv.Itoa(i)+"]", s)
		r.Signatures = append(r.Signatures, Signature{
			KeyID: so.Str("key_id", schema.KeyID),
			Alg:   so.Literal("alg", "ed25519"),
			Sig:   so.Str("sig", schema.SigB64),
			Role:  so.Enum("role", RoleIssuer, RoleCounter),
		})
		so.Done()
	}
	// A projection carries one member a receipt never does: its own signature (§11). Requiring it
	// here is also what keeps the two schemas apart, and refuses a projection with the signature
	// stripped off.
	if projected {
		r.ProjectionSig = o.Str("projection_sig", schema.SigB64)
	}
	o.Done()
	if err := v.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

func validateClaim(v *schema.Validator, path string, val *canonical.Value, projected, legacy bool) Claim {
	var c Claim
	o := v.Object(path, val)
	c.N = o.Int("n", 1, canonical.MaxSafeInteger)
	c.ClaimHMAC = o.Str("claim_hmac", schema.Hex64)
	c.QuoteHMAC = o.StrOrNull("quote_hmac", schema.Hex64)
	c.DocSpan = o.Span("doc_span")

	loc := o.Obj("locator")
	c.Locator.Type = loc.Enum("type", "url", "doi", "pmid", "case", "unsupported")
	if projected {
		c.Locator.Domain = loc.StrOrNull("domain", schema.Domain)
	} else {
		switch c.Locator.Type {
		case "url":
			c.Locator.Value = loc.Str("value", schema.HTTPURL)
			c.Locator.URL = loc.StrOrNull("url", schema.HTTPURL)
		case "doi":
			c.Locator.Value = loc.Str("value", schema.DOI)
			c.Locator.URL = loc.StrOrNull("url", schema.HTTPURL)
		case "pmid":
			c.Locator.Value = loc.Str("value", schema.PMID)
			c.Locator.URL = loc.StrOrNull("url", schema.HTTPURL)
		case "case":
			c.Locator.Value = loc.Str("value", schema.CaseCite)
			c.Locator.URL = loc.StrOrNull("url", schema.HTTPURL)
		case "unsupported":
			c.Locator.Value = loc.Str("value", schema.Hex64)
			loc.Null("url")
		}
	}
	loc.Done()

	if legacy {
		c.SourceOf = o.EnumOr("source_of", "body", "body", "list")
	} else {
		c.SourceOf = o.Enum("source_of", "body", "list")
	}
	c.Level = o.Enum("level", "EXISTS", "SAYS")

	ex := o.Obj("exists")
	c.Exists.Verdict = ex.Enum("verdict", "RESOLVED", "RESOLVED_NO_ACCESS", "NOT_FOUND", "SOURCE_UNREACHABLE", "UNSUPPORTED_LOCATOR")
	if !projected {
		c.Exists.FinalURL = ex.StrOrNull("final_url", schema.HTTPURL)
	}
	c.Exists.HTTPStatus = ex.IntOrNull("http_status", 0, maxStatus)
	c.Exists.FetchedAt = ex.StrOrNull("fetched_at", schema.Timestamp)
	c.Exists.ContentType = ex.StrOrNull("content_type", schema.MediaType)
	c.Exists.Bytes = ex.IntOrNull("bytes", 0, canonical.MaxSafeInteger)
	c.Exists.ContentSHA256 = ex.StrOrNull("content_sha256", schema.Hex64)
	c.Exists.TextSHA256 = ex.StrOrNull("text_sha256", schema.Hex64)
	retPath, rets := ex.Array("retrievers", maxRetrievers)
	for i, rv := range rets {
		ro := v.Object(retPath+"["+strconv.Itoa(i)+"]", rv)
		var ret Retriever
		ret.ID = ro.Str("id", schema.RetrieverID)
		ret.Vantage = ro.Str("vantage", schema.Vantage)
		if sp, sm := ro.Member("status"); sm != nil {
			if sm.Kind == canonical.String && sm.Str == "unavailable" {
				ret.Unavailable = true
			} else {
				ret.Status = schema.Integer(v, sp, sm, 0, maxStatus)
			}
		}
		ret.ContentSHA256 = ro.StrOrNull("content_sha256", schema.Hex64)
		ro.Done()
		c.Exists.Retrievers = append(c.Exists.Retrievers, ret)
	}
	c.Exists.RetrieverDisagreement = ex.Boolean("retriever_disagreement")
	c.Exists.SingleRetriever = ex.Boolean("single_retriever")
	if reg := ex.ObjOrNull("registry"); reg != nil {
		c.Exists.Registry = &Registry{Agency: reg.Str("agency", schema.Token(32)), Status: reg.Int("status", 0, 999)}
		if legacy {
			c.Exists.Registry.Method = reg.StrOrNullOr("method", "lookup", schema.Token(16))
		} else {
			c.Exists.Registry.Method = reg.StrOrNull("method", schema.Token(16))
		}
		// The case registry's members (§4.8.1.1): optional, so a registry that never writes them and
		// a body sealed before they existed both pass; checked to their shape when present. A
		// projection carries no cluster_id (§11): in one it is an unknown member, and Done says so.
		if _, m := reg.Optional("reason"); m != nil {
			c.Exists.Registry.Reason = reg.StrOrNull("reason", schema.Token(48))
		}
		if _, m := reg.Optional("name_check"); m != nil {
			c.Exists.Registry.NameCheck = reg.EnumOrNull("name_check", "match", "mismatch", "uncertain", "not_run")
		}
		if !projected {
			if _, m := reg.Optional("cluster_id"); m != nil {
				c.Exists.Registry.ClusterID = reg.IntOrNull("cluster_id", 0, canonical.MaxSafeInteger)
			}
		}
		reg.Done()
	}
	if !projected {
		c.Exists.ArchiveURL = ex.StrOrNull("archive_url", schema.HTTPURL)
	}
	c.Exists.ArchiveStatus = ex.Enum("archive_status", "archived", "requested", "failed", "skipped")
	c.Exists.ArchiveJobID = ex.StrOrNull("archive_job_id", schema.ArchiveJob)
	ex.Done()

	sa := o.Obj("says")
	c.Says.Verdict = sa.Enum("verdict", "MATCH", "DRIFT", "NOT_FOUND", "NOT_RUN")
	c.Says.Reason = sa.StrOrNull("reason", schema.Token(48))
	c.Says.QuotedSpan = sa.SpanOrNull("quoted_span")
	c.Says.MatchKind = sa.EnumOrNull("match_kind", "exact", "overlap")
	c.Says.OverlapBP = sa.IntOrNull("overlap_bp", 0, maxBP)
	sa.Done()

	c.RefutationAttempted = o.Boolean("refutation_attempted")
	o.Null("dissent")
	o.Done()
	return c
}
