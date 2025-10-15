package perw

import (
	"gosstrip/common"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// buildGoPE builds the Go test executable from testfiles/simple_go.go targeting Windows PE
func buildGoPE(t *testing.T, outName string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("PE execution tests require Windows host")
	}
	td := t.TempDir()
	out := filepath.Join(td, outName)
	cmd := exec.Command("go", "build", "-o", out, filepath.Join("..", "testfiles", "simple_go.go"))
	cmd.Env = os.Environ()
	// Ensure we build for windows; on Windows this is default. Keep as-is.
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build PE sample: %v\n%s", err, string(outBytes))
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("built file missing: %v", err)
	}
	return out
}

func runExe(t *testing.T, exePath string) {
	t.Helper()
	cmd := exec.Command(exePath)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Include output for diagnostics
		t.Fatalf("execution failed: %v\nOutput:\n%s", err, string(out))
	}
}

func extractSectionData(t *testing.T, pePath, sectionName string) []byte {
	t.Helper()
	pef, err := readPe(pePath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
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
	pef, err := readPe(pePath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
	}
	defer func() { _ = pef.Close() }()
	ov, err := pef.ExtractOverlay()
	if err != nil {
		t.Fatalf("extract overlay failed: %v", err)
	}
	return ov
}

func TestPE_Insert_Extract_Run_NoPassword(t *testing.T) {
	host := buildGoPE(t, "host_no_pwd.exe")
	payload := buildGoPE(t, "payload_no_pwd.exe")

	// Insert payload as a new section
	secName := ".payload"
	res := InsertPE(host, common.SanitizeSectionName(secName), payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected insert applied, got %#v", res)
	}

	// Extract section bytes and run as a program
	raw := extractSectionData(t, host, secName)
	outPath := filepath.Join(t.TempDir(), "extracted_payload.exe")
	if err := os.WriteFile(outPath, raw, 0o700); err != nil {
		t.Fatalf("failed to write extracted payload: %v", err)
	}
	runExe(t, outPath)
}

func TestPE_Insert_Extract_Run_WithPassword(t *testing.T) {
	host := buildGoPE(t, "host_pwd.exe")
	payload := buildGoPE(t, "payload_pwd.exe")
	pwd := "secret123"

	res := InsertPE(host, common.SanitizeSectionName(".payenc"), payload, pwd)
	if res == nil || !res.Applied {
		t.Fatalf("expected insert applied, got %#v", res)
	}

	raw := extractSectionData(t, host, ".payenc")
	dec, err := common.DecryptAES256GCM(raw, []byte(pwd))
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "extracted_payload_dec.exe")
	if err := os.WriteFile(outPath, dec, 0o700); err != nil {
		t.Fatalf("failed to write decrypted payload: %v", err)
	}
	runExe(t, outPath)
}

func TestPE_Overlay_Extract_Run_NoPassword(t *testing.T) {
	host := buildGoPE(t, "host_ovl.exe")
	payload := buildGoPE(t, "payload_ovl.exe")

	res := OverlayPE(host, payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}

	ov := extractOverlayData(t, host)
	outPath := filepath.Join(t.TempDir(), "overlay_payload.exe")
	if err := os.WriteFile(outPath, ov, 0o700); err != nil {
		t.Fatalf("failed to write overlay payload: %v", err)
	}
	runExe(t, outPath)
}

func TestPE_Overlay_Extract_Run_WithPassword(t *testing.T) {
	host := buildGoPE(t, "host_ovl_pwd.exe")
	payload := buildGoPE(t, "payload_ovl_pwd.exe")
	pwd := "ovlpass"

	res := OverlayPE(host, payload, pwd)
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}

	ov := extractOverlayData(t, host)
	dec, err := common.DecryptAES256GCM(ov, []byte(pwd))
	if err != nil {
		t.Fatalf("decrypt overlay failed: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "overlay_payload_dec.exe")
	if err := os.WriteFile(outPath, dec, 0o700); err != nil {
		t.Fatalf("failed to write decrypted overlay payload: %v", err)
	}
	runExe(t, outPath)
}

// === New: C on Windows (PE) real-binary tests ===

func hasCL() bool {
	_, err := exec.LookPath("cl.exe")
	return err == nil
}

func hasWinGCC() bool {
	_, err := exec.LookPath("gcc")
	return err == nil
}

// buildCPE builds testfiles/simple.c into a Windows PE executable using cl.exe or gcc.
func buildCPE(t *testing.T, outName string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("C PE build requires Windows host")
	}
	td := t.TempDir()
	out := filepath.Join(td, outName)
	srcRel := filepath.Join("..", "testfiles", "simple.c")
	src, _ := filepath.Abs(srcRel)
	var cmd *exec.Cmd
	if hasCL() {
		// cl /nologo /O2 /Fe:out.exe src.c
		cmd = exec.Command("cl.exe", "/nologo", "/O2", "/Fe:"+out, src)
	} else if hasWinGCC() {
		cmd = exec.Command("gcc", "-O2", "-o", out, src)
	} else {
		t.Skip("No C compiler found (cl.exe or gcc); skipping C PE tests")
	}
	cmd.Env = os.Environ()
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build C PE: %v\n%s", err, string(outBytes))
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("built C PE missing: %v", err)
	}
	return out
}

func TestPE_C_Insert_Extract_Run_NoPassword(t *testing.T) {
	host := buildCPE(t, "host_c_nopwd.exe")
	payload := buildCPE(t, "payload_c_nopwd.exe")
	secName := common.SanitizeSectionName(".cpayload") // ensure <=8 chars
	res := InsertPE(host, secName, payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected insert applied, got %#v", res)
	}
	raw := extractSectionData(t, host, secName)
	outPath := filepath.Join(t.TempDir(), "extracted_c_payload.exe")
	if err := os.WriteFile(outPath, raw, 0o700); err != nil {
		t.Fatalf("write extracted failed: %v", err)
	}
	runExe(t, outPath)
}

func TestPE_C_Insert_Extract_Run_WithPassword(t *testing.T) {
	host := buildCPE(t, "host_c_pwd.exe")
	payload := buildCPE(t, "payload_c_pwd.exe")
	pwd := "csecret"
	res := InsertPE(host, common.SanitizeSectionName(".cpayenc"), payload, pwd)
	if res == nil || !res.Applied {
		t.Fatalf("expected insert applied, got %#v", res)
	}
	raw := extractSectionData(t, host, ".cpayenc")
	dec, err := common.DecryptAES256GCM(raw, []byte(pwd))
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "extracted_c_payload_dec.exe")
	if err := os.WriteFile(outPath, dec, 0o700); err != nil {
		t.Fatalf("failed to write decrypted: %v", err)
	}
	runExe(t, outPath)
}

func TestPE_C_Overlay_Extract_Run_NoPassword(t *testing.T) {
	host := buildCPE(t, "host_c_ovl.exe")
	payload := buildCPE(t, "payload_c_ovl.exe")
	res := OverlayPE(host, payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}
	ov := extractOverlayData(t, host)
	// If host already had overlay, take only the last len(payload) bytes
	pbytes, err := os.ReadFile(payload)
	if err != nil {
		t.Fatalf("read payload failed: %v", err)
	}
	suffix := ov
	if len(ov) > len(pbytes) {
		suffix = ov[len(ov)-len(pbytes):]
	}
	outPath := filepath.Join(t.TempDir(), "overlay_c_payload.exe")
	if err := os.WriteFile(outPath, suffix, 0o700); err != nil {
		t.Fatalf("write overlay failed: %v", err)
	}
	runExe(t, outPath)
}

func TestPE_C_Overlay_Extract_Run_WithPassword(t *testing.T) {
	host := buildCPE(t, "host_c_ovl_pwd.exe")
	payload := buildCPE(t, "payload_c_ovl_pwd.exe")
	pwd := "ovlcpass"
	res := OverlayPE(host, payload, pwd)
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}
	ov := extractOverlayData(t, host)
	pbytes, err := os.ReadFile(payload)
	if err != nil {
		t.Fatalf("read payload failed: %v", err)
	}
	// GCM output = nonce(12) + ciphertext(len(payload)) + tag(16)
	ctLen := len(pbytes) + 28
	ct := ov
	if len(ov) >= ctLen {
		ct = ov[len(ov)-ctLen:]
	}
	dec, err := common.DecryptAES256GCM(ct, []byte(pwd))
	if err != nil {
		t.Fatalf("decrypt overlay failed: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "overlay_c_payload_dec.exe")
	if err := os.WriteFile(outPath, dec, 0o700); err != nil {
		t.Fatalf("write decrypted overlay failed: %v", err)
	}
	runExe(t, outPath)
}
