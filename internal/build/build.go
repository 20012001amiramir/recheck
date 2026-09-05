// Package build carries what the build stamps into a binary.
package build

// Version is set by the linker:
// -ldflags "-X github.com/20012001amiramir/recheck/internal/build.Version=v0.1.0".
// It has no initializer on purpose: TinyGo runs an initializer as a store during package init,
// on top of what the linker put there.
var Version string

// String is the version, or "dev" for a build that stamped none.
func String() string {
	if Version == "" {
		return "dev"
	}
	return Version
}
