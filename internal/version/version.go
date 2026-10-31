// Package version reports which build of Valet is running.
package version

import "runtime/debug"

// Version is set at build time with
// -ldflags "-X github.com/xcwds/valet/internal/version.Version=v0.1.0".
// When it is unset, String falls back to the module version recorded by
// `go install` and then to "dev".
var Version = ""

// String returns the version of this build.
func String() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}
