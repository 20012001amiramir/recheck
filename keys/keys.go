// Package keys carries the issuer keys pinned into a release build of recheck.
//
// exhibitb.json has the shape of the issuer's /keys.json. It is empty in the source tree on
// purpose: the deploy step copies the production key set in before a release is built, and the
// test fixture keys under spec/vectors are never pinned (spec §13).
package keys

import _ "embed"

// Pinned is the raw JSON of keys/exhibitb.json.
//
//go:embed exhibitb.json
var Pinned []byte
