// Package keys carries the issuer keys pinned into a build of recheck.
//
// exhibitb.json has the shape of the issuer's /keys.json and lists the production keys; it is
// refreshed from the published key set before a release is built. The fixture key under
// spec/vectors is never pinned (spec §13): a receipt sealed under it reports key_pinned warn
// unless the fixture is passed with --keys.
package keys

import _ "embed"

// Pinned is the raw JSON of keys/exhibitb.json.
//
//go:embed exhibitb.json
var Pinned []byte
