//go:build integration
// +build integration

package test

import (
	"fmt"
	"gosstrip/elfrw"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func buildELFInWSL(t *testing.T, outName string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("WSL-based ELF build requires Windows host")
	}
	if !hasWSL() {
		t.Skip("WSL not available; skipping ELF integration tests")
	}
	if !wslHasTool("gcc") {
		t.Skip("WSL is available but gcc is not installed in the distro; skipping ELF integration tests")
	}
	td := t.TempDir()
	outWin := filepath.Join(td, outName)
	srcWin := filepath.Join("..", "testfiles", "simple.c")
	srcAbs, _ := filepath.Abs(srcWin)
	outAbs, _ := filepath.Abs(outWin)
	cmd := fmt.Sprintf("gcc -O2 '%s' -o '%s' -lm", toWSLPath(srcAbs), toWSLPath(outAbs))
	if err := wslRun(cmd); err != nil {
		t.Fatalf("failed to build ELF sample in WSL: %v", err)
	}
	if _, err := os.Stat(outWin); err != nil {
		t.Fatalf("built ELF file missing: %v", err)
	}
	return outWin
}

func runELFInWSL(t *testing.T, pathWin string) {
	t.Helper()
	if err := wslRun("'" + toWSLPath(pathWin) + "'"); err != nil {
		t.Fatalf("ELF run failed: %v", err)
	}
}

func extractELFSectionData(t *testing.T, elfPath, sectionName string) []byte {
	t.Helper()
	f, err := os.Open(elfPath)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
	}
	defer func() { _ = f.Close() }()
	ef, err := elfrw.ReadELF(f)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}
	defer func() { _ = ef.Close() }()
	var idx int = -1
	for i, s := range ef.Sections {
		if s.Name == sectionName {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("section %q not found", sectionName)
	}
	sec := ef.Sections[idx]
	data := make([]byte, sec.Size)
	if _, err := f.ReadAt(data, sec.Offset); err != nil {
		t.Fatalf("failed reading section bytes: %v", err)
	}
	return data
}

func extractELFOverlay(t *testing.T, elfPath string) []byte {
	t.Helper()
	f, err := os.Open(elfPath)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
	}
	defer func() { _ = f.Close() }()
	ef, err := elfrw.ReadELF(f)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}
	defer func() { _ = ef.Close() }()
	overlay, err := ef.ExtractOverlay()
	if err != nil {
		t.Fatalf("extract overlay failed: %v", err)
	}
	return overlay
}

func TestELF_Insert_Extract_WSL(t *testing.T) {
	host := buildELFInWSL(t, "host")
	payload := buildELFInWSL(t, "payload")

	if result := elfrw.InsertELF(host, ".payload", payload, ""); result == nil || !result.Applied {
		t.Fatalf("expected insert to apply: %#v", result)
	}

	section := extractELFSectionData(t, host, ".payload")
	if len(section) == 0 {
		t.Fatalf("expected payload section bytes")
	}

	runELFInWSL(t, host)
}

func TestELF_Insert_Overlay_WSL(t *testing.T) {
	host := buildELFInWSL(t, "host_overlay")
	payload := buildELFInWSL(t, "payload_overlay")

	if result := elfrw.InsertELF(host, ".payload", payload, ""); result == nil || !result.Applied {
		t.Fatalf("expected insert to apply: %#v", result)
	}
	if result := elfrw.OverlayELF(host, payload, ""); result == nil || !result.Applied {
		t.Fatalf("expected overlay to apply: %#v", result)
	}

	if data := extractELFSectionData(t, host, ".payload"); len(data) == 0 {
		t.Fatalf("expected section payload data")
	}
	if overlay := extractELFOverlay(t, host); len(overlay) == 0 {
		t.Fatalf("expected overlay data")
	}
	runELFInWSL(t, host)
}

func TestELF_Overlay_WithPassword(t *testing.T) {
	host := buildELFInWSL(t, "host_overlay_pwd")
	payload := buildELFInWSL(t, "payload_overlay_pwd")
	password := "overlay_secret"

	if result := elfrw.InsertELF(host, ".payload", payload, password); result == nil || !result.Applied {
		t.Fatalf("expected insert to apply: %#v", result)
	}
	if result := elfrw.OverlayELF(host, payload, password); result == nil || !result.Applied {
		t.Fatalf("expected overlay to apply: %#v", result)
	}

	if data := extractELFSectionData(t, host, ".payload"); len(data) == 0 {
		t.Fatalf("expected encrypted section payload data")
	}
	if overlay := extractELFOverlay(t, host); len(overlay) == 0 {
		t.Fatalf("expected encrypted overlay data")
	}
	runELFInWSL(t, host)
}
