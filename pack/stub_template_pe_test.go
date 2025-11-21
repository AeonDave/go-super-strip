package pack

import (
	"strings"
	"testing"

	stratcommon "gosstrip/pack/strategies/common"
)

func TestPEStubIncludesEarlyBirdAtomic(t *testing.T) {
	code := GetPEStubSource("amd64", stratcommon.ModeEarlyBirdAtomic)
	if !strings.Contains(code, "executeEarlyBirdAtomicBombing") {
		t.Fatalf("stub for early_bird_atomic_bombing missing runtime")
	}
}

func TestPEStubIncludesDoppel(t *testing.T) {
	code := GetPEStubSource("amd64", stratcommon.ModeProcessDoppel)
	if !strings.Contains(code, "executeProcessDoppelganging") {
		t.Fatalf("stub for process_doppelganging missing runtime")
	}
}

func TestPEStubIncludesDoppel32(t *testing.T) {
	code := GetPEStubSource("386", stratcommon.ModeProcessDoppel)
	if !strings.Contains(code, "executeProcessDoppelganging") {
		t.Fatalf("stub for process_doppelganging (32-bit) missing runtime")
	}
}

func TestPEStubIncludesTransacted(t *testing.T) {
	code := GetPEStubSource("amd64", stratcommon.ModeTransactedHollow)
	if !strings.Contains(code, "executeTransactedHollowing") {
		t.Fatalf("stub for transacted_hollowing missing runtime")
	}
}

func TestPEStubIncludesTransacted32(t *testing.T) {
	code := GetPEStubSource("386", stratcommon.ModeTransactedHollow)
	if !strings.Contains(code, "executeTransactedHollowing") {
		t.Fatalf("stub for transacted_hollowing (32-bit) missing runtime")
	}
}
