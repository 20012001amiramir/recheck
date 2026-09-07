// Package receipt parses, checks and projects EXHIBIT B receipts (spec/RECEIPT.md §4, §11, §12).
package receipt

// Constants fixed by the spec.
const (
	KindChained   = "exhibitb.receipt"
	KindUnchained = "exhibitb.receipt.unchained"
	IssuerName    = "EXHIBIT B"
	// ScopeDisclaimer is the literal every receipt carries (§4.2).
	ScopeDisclaimer = "Attests what was checked, against which sources, at what time. Not a claim of truth."
	RoleIssuer      = "issuer"
	RoleCounter     = "counter"
	// MaxSignatures is the most entries a signatures array may hold.
	MaxSignatures = 8
)

// Receipt is a receipt v1 (§4) or, when Projected is true, its public projection (§11). Pointer
// members are the ones the spec marks `| null`.
type Receipt struct {
	V               int64
	Kind            string
	ID              string
	Seq             *int64
	PrevHash        *string
	IssuedAt        string
	Issuer          Issuer
	ScopeDisclaimer string
	Document        Document
	Binding         Binding
	Claims          []Claim
	Counts          Counts
	Models          []Model
	Engine          Engine
	SelfHash        string
	Signatures      []Signature
	// ProjectionSig is a projection's own signature (§11): ed25519 by the receipt key over the
	// projection self-hash. Empty on a full receipt, which never carries it.
	ProjectionSig string
	// Projected marks a public projection: cited URLs are gone, self_hash is not recomputed, and
	// projection_sig binds the visible fields instead.
	Projected bool
}

// Issuer is §4.3.
type Issuer struct {
	Name      string
	URL       string
	KeyID     string
	PublicKey string
}

// Document is §4.4.
type Document struct {
	SHA256     string
	Bytes      int64
	MediaType  string
	TextSHA256 string
	Chars      int64
	Extractor  string
}

// Binding is §4.5.
type Binding struct {
	Alg       string
	KeySHA256 string
}

// Claim is §4.6.
type Claim struct {
	N                   int64
	ClaimHMAC           string
	QuoteHMAC           *string
	DocSpan             [2]int64
	Locator             Locator
	// SourceOf is "body" or "list": which of the two kinds of claim this is (§4.6).
	SourceOf            string
	Level               string
	Exists              Exists
	Says                Says
	RefutationAttempted bool
}

// Locator is §4.7. In a receipt Value and URL are set; in a projection only Domain is.
type Locator struct {
	Type   string
	Value  string
	URL    *string
	Domain *string
}

// Exists is §4.8.1. FinalURL and ArchiveURL are absent from a projection.
type Exists struct {
	Verdict               string
	FinalURL              *string
	HTTPStatus            *int64
	FetchedAt             *string
	ContentType           *string
	Bytes                 *int64
	ContentSHA256         *string
	TextSHA256            *string
	Retrievers            []Retriever
	RetrieverDisagreement bool
	SingleRetriever       bool
	Registry              *Registry
	ArchiveURL            *string
	ArchiveStatus         string
	ArchiveJobID          *string
}

// Retriever is one vantage point's answer. Unavailable is true when status was the literal
// "unavailable" rather than an HTTP status.
type Retriever struct {
	ID            string
	Vantage       string
	Status        int64
	Unavailable   bool
	ContentSHA256 *string
}

// Registry is the registry consulted for a doi/pmid/case locator.
type Registry struct {
	Agency string
	Status int64
	// Method names the call that answered, when the registry has more than one; null otherwise (§4.8.1).
	Method *string
}

// Says is §4.8.2.
type Says struct {
	Verdict    string
	Reason     *string
	QuotedSpan *[2]int64
	MatchKind  *string
	OverlapBP  *int64
}

// Counts is §4.9: the issuer's tallies, informational to a verifier.
type Counts struct {
	Claims int64
	// NotChecked is the citations the engine found and did not check, because a budget bound (§4.9).
	NotChecked     int64
	Resolved       int64
	NoAccess       int64
	NotFound       int64
	Unreachable    int64
	Unsupported    int64
	SaysMatch      int64
	SaysDrift      int64
	SaysNotFound   int64
	SaysNotRun     int64
	HoldsAttempted int64
}

// Model is §4.10.
type Model struct {
	Role  string
	Model string
}

// Engine is §4.11.
type Engine struct {
	Name       string
	Version    string
	Normalize  string
	MatchBP    int64
	DriftMinBP int64
}

// Signature is §4.12.
type Signature struct {
	KeyID string
	Alg   string
	Sig   string
	Role  string
}

// IssuerSignatures returns the entries whose role is "issuer" — exactly one in a valid receipt.
func (r *Receipt) IssuerSignatures() []Signature {
	var out []Signature
	for _, s := range r.Signatures {
		if s.Role == RoleIssuer {
			out = append(out, s)
		}
	}
	return out
}
