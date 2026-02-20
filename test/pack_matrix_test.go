//go:build integration
// +build integration

package test

import (
	"fmt"
	"runtime"
	"testing"

	"gosstrip/pack"
)

func TestPEPackingMatrix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE packing matrix requires Windows host")
	}
	t.Setenv("GOSSTRIP_TEST_STUB", "")

	fixture := buildProbeFixture(t, "windows", "probe.exe")
	compressions := []string{"xz", "lzma", "none"}
	encryption := []string{"aes-256-gcm", "chacha20", "none"}
	inmemory := []string{
		"off",
		"auto",
		"process_hollowing",
		"atomic_bombing",
		"early_bird",
		"early_bird_atomic_bombing",
		"process_doppelganging",
		"transacted_hollowing",
		"self_injection",
		"nt_syscall_reflective",
		"reflective_loader",
	}

	for _, comp := range compressions {
		for _, enc := range encryption {
			for _, mode := range inmemory {
				name := fmt.Sprintf("%s_%s_%s", comp, enc, mode)
				t.Run(name, func(t *testing.T) {
					work := copyBinary(t, fixture)
					opts := fmt.Sprintf("compression=%s,encryption=%s,inmemory=%s", comp, enc, mode)
					if err := pack.Pack(work, opts, work); err != nil {
						t.Fatalf("pack failed: %v", err)
					}
					runPEBinary(t, work)
				})
			}
		}
	}
}

func TestELFPackingMatrix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF packing matrix requires a Linux host")
	}
	t.Setenv("GOSSTRIP_TEST_STUB", "")

	fixture := buildProbeFixture(t, "linux", "probe")
	compressions := []string{"xz", "lzma", "none"}
	encryption := []string{"aes-256-gcm", "chacha20", "none"}
	inmemory := []string{"off", "auto", "memfd"}

	for _, comp := range compressions {
		for _, enc := range encryption {
			for _, mode := range inmemory {
				name := fmt.Sprintf("%s_%s_%s", comp, enc, mode)
				t.Run(name, func(t *testing.T) {
					work := copyBinary(t, fixture)
					opts := fmt.Sprintf("compression=%s,encryption=%s,inmemory=%s", comp, enc, mode)
					if err := pack.Pack(work, opts, work); err != nil {
						t.Fatalf("pack failed: %v", err)
					}
					runELFBinary(t, work)
				})
			}
		}
	}
}
