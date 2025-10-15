package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func hasWSL() bool {
	_, err := exec.LookPath("wsl.exe")
	return err == nil
}

func toWSLPath(win string) string {
	// Convert like: D:\path\to -> /mnt/d/path/to
	if len(win) < 3 || win[1] != ':' {
		return win
	}
	drive := strings.ToLower(string(win[0]))
	p := strings.ReplaceAll(win[2:], "\\", "/")
	return "/mnt/" + drive + p
}

func wslRun(cmd string) error {
	c := exec.Command("wsl.exe", "bash", "-lc", cmd)
	c.Env = os.Environ()
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("WSL command failed: %v\n%s", err, string(out))
	}
	return nil
}

func buildELFInWSL(t *testing.T, outName string) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("WSL-based ELF build requires Windows host")
	}
	if !hasWSL() {
		t.Skip("WSL not available; skipping ELF integration tests")
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
	ef, err := readElf(elfPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
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
		t.Fatalf("section %s not found", sectionName)
	}
	content, err := ef.ELF.GetSectionContent(uint16(ef.Sections[idx].Index))
	if err != nil {
		t.Fatalf("failed to read section content: %v", err)
	}
	return append([]byte(nil), content...)
}

func extractELFOverlayData(t *testing.T, elfPath string) []byte {
	t.Helper()
	ef, err := readElf(elfPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
	}
	defer func() { _ = ef.Close() }()
	ov, err := ef.ExtractOverlay()
	if err != nil {
		t.Fatalf("extract overlay failed: %v", err)
	}
	return ov
}

func TestELF_Insert_Extract_Run_NoPassword(t *testing.T) {
	host := buildELFInWSL(t, "host_elf")
	payload := buildELFInWSL(t, "payload_elf")

	res := InsertELF(host, ".payload", payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected insert applied, got %#v", res)
	}

	raw := extractELFSectionData(t, host, ".payload")
	out := filepath.Join(t.TempDir(), "ex_payload_elf")
	if err := os.WriteFile(out, raw, 0o700); err != nil {
		t.Fatalf("failed to write extracted payload: %v", err)
	}
	runELFInWSL(t, out)
}

func TestELF_Insert_Extract_Run_WithPassword(t *testing.T) {
	host := buildELFInWSL(t, "host_elf_pwd")
	payload := buildELFInWSL(t, "payload_elf_pwd")
	pwd := "secret123"

	res := InsertELF(host, ".payenc", payload, pwd)
	if res == nil || !res.Applied {
		t.Fatalf("expected insert applied, got %#v", res)
	}

	raw := extractELFSectionData(t, host, ".payenc")
	dec, err := common.DecryptAES256GCM(raw, []byte(pwd))
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	out := filepath.Join(t.TempDir(), "ex_payload_elf_dec")
	if err := os.WriteFile(out, dec, 0o700); err != nil {
		t.Fatalf("failed to write decrypted payload: %v", err)
	}
	runELFInWSL(t, out)
}

func TestELF_Overlay_Extract_Run_NoPassword(t *testing.T) {
	host := buildELFInWSL(t, "host_elf_ovl")
	payload := buildELFInWSL(t, "payload_elf_ovl")

	res := OverlayELF(host, payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}
	ov := extractELFOverlayData(t, host)
	pbytes, err := os.ReadFile(payload)
	if err != nil {
		t.Fatalf("read payload failed: %v", err)
	}
	suffix := ov
	if len(ov) > len(pbytes) {
		suffix = ov[len(ov)-len(pbytes):]
	}
	out := filepath.Join(t.TempDir(), "ovl_payload_elf")
	if err := os.WriteFile(out, suffix, 0o700); err != nil {
		t.Fatalf("failed to write overlay payload: %v", err)
	}
	runELFInWSL(t, out)
}

func TestELF_Overlay_Extract_Run_WithPassword(t *testing.T) {
	host := buildELFInWSL(t, "host_elf_ovl_pwd")
	payload := buildELFInWSL(t, "payload_elf_ovl_pwd")
	pwd := "ovlpass"

	res := OverlayELF(host, payload, pwd)
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}
	ov := extractELFOverlayData(t, host)
	pbytes, err := os.ReadFile(payload)
	if err != nil {
		t.Fatalf("read payload failed: %v", err)
	}
	// AES-GCM output size = len(payload) + 12 nonce + 16 tag
	ctLen := len(pbytes) + 28
	ct := ov
	if len(ov) >= ctLen {
		ct = ov[len(ov)-ctLen:]
	}
	dec, err := common.DecryptAES256GCM(ct, []byte(pwd))
	if err != nil {
		t.Fatalf("decrypt overlay failed: %v", err)
	}
	out := filepath.Join(t.TempDir(), "ovl_payload_elf_dec")
	if err := os.WriteFile(out, dec, 0o700); err != nil {
		t.Fatalf("failed to write decrypted overlay payload: %v", err)
	}
	runELFInWSL(t, out)
}

// === New: Go on Linux (ELF) real-binary tests via WSL ===

// buildGoELF cross-compiles testfiles/simple_go.go to a Linux ELF binary.
func buildGoELF(t *testing.T, outName string) string {
	t.Helper()
	td := t.TempDir()
	out := filepath.Join(td, outName)
	src := filepath.Join("..", "testfiles", "simple_go.go")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to cross-compile Go ELF: %v\n%s", err, string(outBytes))
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("built Go ELF missing: %v", err)
	}
	return out
}

func TestELF_Go_Insert_Extract_Run_NoPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL-based ELF run requires Windows host")
	}
	if !hasWSL() {
		t.Skip("WSL not available; skipping Go ELF integration tests")
	}
	host := buildGoELF(t, "host_go_elf")
	payload := buildGoELF(t, "payload_go_elf")
	res := InsertELF(host, ".payload", payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected insert applied, got %#v", res)
	}
	raw := extractELFSectionData(t, host, ".payload")
	out := filepath.Join(t.TempDir(), "ex_go_payload")
	if err := os.WriteFile(out, raw, 0o700); err != nil {
		t.Fatalf("failed to write extracted payload: %v", err)
	}
	runELFInWSL(t, out)
}

func TestELF_Go_Insert_Extract_Run_WithPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL-based ELF run requires Windows host")
	}
	if !hasWSL() {
		t.Skip("WSL not available; skipping Go ELF integration tests")
	}
	host := buildGoELF(t, "host_go_elf_pwd")
	payload := buildGoELF(t, "payload_go_elf_pwd")
	pwd := "gosecret"
	res := InsertELF(host, ".payenc", payload, pwd)
	if res == nil || !res.Applied {
		t.Fatalf("expected insert applied, got %#v", res)
	}
	raw := extractELFSectionData(t, host, ".payenc")
	dec, err := common.DecryptAES256GCM(raw, []byte(pwd))
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	out := filepath.Join(t.TempDir(), "ex_go_payload_dec")
	if err := os.WriteFile(out, dec, 0o700); err != nil {
		t.Fatalf("failed to write decrypted payload: %v", err)
	}
	runELFInWSL(t, out)
}

func TestELF_Go_Overlay_Extract_Run_NoPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL-based ELF run requires Windows host")
	}
	if !hasWSL() {
		t.Skip("WSL not available; skipping Go ELF integration tests")
	}
	host := buildGoELF(t, "host_go_elf_ovl")
	payload := buildGoELF(t, "payload_go_elf_ovl")
	res := OverlayELF(host, payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}
	ov := extractELFOverlayData(t, host)
	out := filepath.Join(t.TempDir(), "ovl_go_payload")
	if err := os.WriteFile(out, ov, 0o700); err != nil {
		t.Fatalf("failed to write overlay payload: %v", err)
	}
	runELFInWSL(t, out)
}

func TestELF_Go_Overlay_Extract_Run_WithPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("WSL-based ELF run requires Windows host")
	}
	if !hasWSL() {
		t.Skip("WSL not available; skipping Go ELF integration tests")
	}
	host := buildGoELF(t, "host_go_elf_ovl_pwd")
	payload := buildGoELF(t, "payload_go_elf_ovl_pwd")
	pwd := "ovlgopass"
	res := OverlayELF(host, payload, pwd)
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}
	ov := extractELFOverlayData(t, host)
	dec, err := common.DecryptAES256GCM(ov, []byte(pwd))
	if err != nil {
		t.Fatalf("decrypt overlay failed: %v", err)
	}
	out := filepath.Join(t.TempDir(), "ovl_go_payload_dec")
	if err := os.WriteFile(out, dec, 0o700); err != nil {
		t.Fatalf("failed to write decrypted overlay payload: %v", err)
	}
	runELFInWSL(t, out)
}
