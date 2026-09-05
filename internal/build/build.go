// Package build carries what the build stamps into a binary.
package build

// Version is set by the linker:
// -ldflags "-X github.com/20012001amiramir/recheck/internal/build.Version=v0.1.0".
var Version = "dev"
