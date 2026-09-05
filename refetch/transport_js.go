//go:build js && wasm

package refetch

// Under a JavaScript host the standard library's transport is fetch(), which follows redirects on
// its own unless told not to — and then the redirect check above, with its issuer guard, would
// never see a hop. Manual mode hands every 3xx back to the Go client, which consults CheckRedirect
// for each one. The header is consumed by the transport, never sent.
var transportHeaders = map[string]string{"js.fetch:redirect": "manual"}
