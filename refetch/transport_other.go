//go:build !(js && wasm)

package refetch

// The native transport follows redirects through the client, so CheckRedirect already sees every
// hop and nothing extra is needed.
var transportHeaders map[string]string
