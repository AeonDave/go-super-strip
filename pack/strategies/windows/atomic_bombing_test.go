package windows

import (
	"strings"
	"testing"
)

// Sanity check that the atomic dispatcher hooks Early Bird correctly.
func TestAtomicEarlyBirdWiring(t *testing.T) {
	src := AtomicBombingRuntime
	if !strings.Contains(src, "executeEarlyBirdAtomicBombing") {
		t.Fatalf("atomic runtime missing Early Bird entry")
	}
}
