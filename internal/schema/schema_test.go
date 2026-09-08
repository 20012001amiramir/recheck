package schema_test

import (
	"strings"
	"testing"

	"github.com/20012001amiramir/recheck/internal/schema"
)

// The case-citation families the app's extractor produces (its tests/receipt.test.ts), and the
// prose-shaped strings it must keep out.
func TestCaseCite(t *testing.T) {
	accept := []string{
		"410 U.S. 113",
		"123 S. Ct. 456",
		"123 S.Ct. 456",
		"123 F. Supp. 2d 456",
		"123 F.3d 456",
		"12 Cal. App. 4th 345",
		"12 Cal.App.4th 345",
		"12 N.Y.S.2d 34",
		"12 Wn. App. 34",
		"12 Ill. App. 34",
		"12 So. 2d 34",
		"12 Neb. 34",
		"[2019] EWHC 12",
		"[2020] UKSC 1",
		"[2019] NSWSC 12",
		"2019 BCSC 5",
		"2019 ONSC 123",
		"2019 SCC 5",
		// The law-report family: a volume after the bracketed year.
		"[2010] 1 AC 123",
		"[2019] 2 WLR 456",
		"[2020] 1 All ER 123",
		"[2015] 2 Lloyd's Rep 123",
		// One whitespace character of the ECMAScript set, not only a space.
		"410 U.S. 113",
		"[2010]\t1 AC 123",
	}
	for _, s := range accept {
		if why := schema.CaseCite(s); why != "" {
			t.Errorf("%q refused: %s", s, why)
		}
	}
	reject := []string{
		"410  U.S. 113",                        // two spaces: the engine collapses runs before sealing
		"410 U.S.",                             // no page
		"410 u.s. 113",                         // reporter must start with a capital
		"12 Cal. App. 4th Ed. 345",             // four reporter tokens
		"1234 Californian Appellate Reports 5", // a reporter token longer than a reporter
		"[2019] EWHC 12 (Ch)",                  // a bracketed division is not part of the value
		"2019 SCC 5 and then some words 6",
		"[2010] 1 ac 123",       // the reporter after a volume must start with a capital too
		"[2010] 1234 AC 123",    // a volume has at most three digits
		"[2010] 1 AC",           // no page
		"[2020] 1 Cr App R 123", // six tokens: outside the five-token envelope on purpose
		"12345 U.S. 113",        // a volume has at most four digits
		"[201] EWHC 12",         // a bracketed year has four digits
		"410 U.S. 1234567",      // a page has at most six digits
		"",
		" 410 U.S. 113",
		"410 U.S. 113 ",
		"[2015] 2 Lloyd's Rep 12345678",         // over 30 characters
		"12 " + strings.Repeat("A", 14) + " 34", // first reporter token longer than 13
		"12 Cal. " + strings.Repeat("A", 9) + " 345", // further reporter token longer than 8
	}
	for _, s := range reject {
		if schema.CaseCite(s) == "" {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestShapes(t *testing.T) {
	ok := map[string]schema.Shape{
		"2026-09-03T11:22:44Z":        schema.Timestamp,
		"2026-09-03":                  schema.Date,
		"application/pdf":             schema.MediaType,
		"unpdf@1":                     schema.Extractor,
		"extract-model-2026-06":       schema.ModelID,
		"1.2.3-rc.1":                  schema.Semver,
		"eb-receipt-2026-09-2":        schema.KeyID,
		"eb_2m4Kq8Xr7vTb3nHd":         schema.ReceiptID,
		"10.1136/bmj.n1234":           schema.DOI,
		"31234567":                    schema.PMID,
		"https://example.org/a?b=1#c": schema.HTTPURL,
		"example.org":                 schema.Domain,
	}
	for s, shape := range ok {
		if why := shape(s); why != "" {
			t.Errorf("%q refused: %s", s, why)
		}
	}
	bad := map[string]schema.Shape{
		"2026-09-03T11:22:44.000Z": schema.Timestamp,
		"eb-Receipt-test":          schema.KeyID,
		"eb_2m4Kq8Xr7vTb3nH0":      schema.ReceiptID, // 0 is not in the alphabet
		"10.12/x":                  schema.DOI,
		"1234567890":               schema.PMID,
		"ftp://example.org":        schema.HTTPURL,
		"https://example.org/a b":  schema.HTTPURL,
		"https://example.org/a　b":  schema.HTTPURL,
		"Example.org":              schema.Domain,
	}
	for s, shape := range bad {
		if shape(s) == "" {
			t.Errorf("%q accepted", s)
		}
	}
	if schema.UTF16Len("a\U0001F600") != 3 {
		t.Error("UTF16Len counts a surrogate pair as two units")
	}
}

// The compatibility rule (§15) is keyed on the numeric triple: a pre-release or build suffix is
// ignored, and a string that is not a semver is not before anything.
func TestSemverBefore(t *testing.T) {
	for _, v := range []string{"0.1.0", "0.1.9", "0.0.1", "0.1.0-rc.1", "0.1.0+build.7"} {
		if !schema.SemverBefore(v, 0, 2, 0) {
			t.Errorf("%s must be before 0.2.0", v)
		}
	}
	for _, v := range []string{"0.2.0", "0.2.0-rc.1", "0.2.1", "0.10.0", "1.0.0", "nope", ""} {
		if schema.SemverBefore(v, 0, 2, 0) {
			t.Errorf("%s must not be before 0.2.0", v)
		}
	}
}
