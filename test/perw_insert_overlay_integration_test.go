package test

import (
	"gosstrip/perw"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func runExe(t *testing.T, exePath string) {
	t.Helper()
	cmd := exec.Command(exePath)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("execution failed: %v\nOutput:\n%s", err, string(out))
	}
}

func extractSectionData(t *testing.T, pePath, sectionName string) []byte {
	t.Helper()
	f, err := os.Open(pePath)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
	}
	defer func() { _ = f.Close() }()
	pef, err := perw.ReadPE(f)
	if err != nil {
		t.Fatalf("failed to parse PE: %v", err)
	}
	defer func() { _ = pef.Close() }()
	sec, err := pef.GetSectionByName(sectionName)
	if err != nil {
		t.Fatalf("section not found: %v", err)
	}
	data, err := pef.ReadBytes(sec.Offset, int(sec.VirtualSize))
	if err != nil {
		t.Fatalf("failed reading section bytes: %v", err)
	}
	return append([]byte(nil), data...)
}

func extractOverlayData(t *testing.T, pePath string) []byte {
	t.Helper()
	f, err := os.Open(pePath)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
	}
	defer func() { _ = f.Close() }()
	pef, err := perw.ReadPE(f)
	if err != nil {
		t.Fatalf("failed to parse PE: %v", err)
	}
	defer func() { _ = pef.Close() }()
	ov, err := pef.ExtractOverlay()
	if err != nil {
		t.Fatalf("extract overlay failed: %v", err)
	}
	return ov
}

func TestPE_Insert_Extract_Run_NoPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE execution tests require Windows host")
	}
	host := buildGoPEBinary(t, "host_no_pwd.exe")
	payload := buildGoPEBinary(t, "payload_no_pwd.exe")

	result := perw.InsertPE(host, ".payload", payload, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected insert to succeed: %#v", result)
	}

	extracted := extractSectionData(t, host, ".payload")
	if len(extracted) == 0 {
		t.Fatalf("expected payload section to contain data")
	}

	runExe(t, host)
}

func TestPE_Insert_Extract_Run_WithPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE execution tests require Windows host")
	}
	host := buildGoPEBinary(t, "host_pwd.exe")
	payload := buildGoPEBinary(t, "payload_pwd.exe")

	password := "super_secret_pwd"
	result := perw.InsertPE(host, ".payload", payload, password)
	if result == nil || !result.Applied {
		t.Fatalf("expected insert to succeed: %#v", result)
	}

	extracted := extractSectionData(t, host, ".payload")
	if len(extracted) == 0 {
		t.Fatalf("expected payload section to contain data")
	}
	runExe(t, host)
}

func TestPE_Insert_Overlay_NoPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE execution tests require Windows host")
	}
	host := buildGoPEBinary(t, "host_ovl.exe")
	payload := buildGoPEBinary(t, "payload_ovl.exe")

	if result := perw.InsertPE(host, ".payload", payload, ""); result == nil || !result.Applied {
		t.Fatalf("section insert failed: %#v", result)
	}
	if result := perw.OverlayPE(host, payload, ""); result == nil || !result.Applied {
		t.Fatalf("overlay insert failed: %#v", result)
	}

	sectionData := extractSectionData(t, host, ".payload")
	if len(sectionData) == 0 {
		t.Fatalf("expected section payload data")
	}
	overlay := extractOverlayData(t, host)
	if len(overlay) == 0 {
		t.Fatalf("expected overlay payload data")
	}
	runExe(t, host)
}

func TestPE_Insert_Overlay_WithPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE execution tests require Windows host")
	}
	host := buildGoPEBinary(t, "host_ovl_pwd.exe")
	payload := buildGoPEBinary(t, "payload_ovl_pwd.exe")
	password := "overlay_secret"

	if result := perw.InsertPE(host, ".payload", payload, password); result == nil || !result.Applied {
		t.Fatalf("section insert failed: %#v", result)
	}
	if result := perw.OverlayPE(host, payload, password); result == nil || !result.Applied {
		t.Fatalf("overlay insert failed: %#v", result)
	}

	sectionData := extractSectionData(t, host, ".payload")
	if len(sectionData) == 0 {
		t.Fatalf("expected encrypted section payload data")
	}
	overlay := extractOverlayData(t, host)
	if len(overlay) == 0 {
		t.Fatalf("expected encrypted overlay payload data")
	}
	runExe(t, host)
}
