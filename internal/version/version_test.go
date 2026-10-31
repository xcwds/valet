package version

import "testing"

func TestStringUsesLinkerVersion(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })

	Version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("String() = %q, want %q", got, "v1.2.3")
	}
}

func TestStringFallsBack(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })

	Version = ""
	// Test binaries have no module version, so the fallback is "dev".
	if got := String(); got != "dev" {
		t.Fatalf("String() = %q, want %q", got, "dev")
	}
}
