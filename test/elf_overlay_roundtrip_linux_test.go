//go:build linux

package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gosstrip/common"
	"gosstrip/elfrw"
)

func buildNativeELF(t *testing.T, outName string) string {
	t.Helper()
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available; skipping native ELF build test")
	}

	td := t.TempDir()
	out := filepath.Join(td, outName)

	cmd := exec.Command("gcc", "-O2", filepath.Join("testfiles", "simple.c"), "-o", out, "-lm")
	cmd.Dir = ".."
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc failed: %v\n%s", err, string(outBytes))
	}

	if _, err := os.Stat(out); err != nil {
		t.Fatalf("compiled file missing: %v", err)
	}

	return out
}

func extractELFOverlayData(t *testing.T, elfPath string) []byte {
	t.Helper()

	file, err := os.Open(elfPath)
	if err != nil {
		t.Fatalf("failed to open ELF: %v", err)
	}
	defer file.Close()

	elfFile, err := elfrw.ReadELF(file)
	if err != nil {
		t.Fatalf("ReadELF returned error: %v", err)
	}
	defer func() { _ = elfFile.Close() }()

	overlay, err := elfFile.ExtractOverlay()
	if err != nil {
		t.Fatalf("extract overlay failed: %v", err)
	}

	return overlay
}

func locateOverlayPayload(overlay, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	idx := bytes.Index(overlay, payload)
	if idx == -1 {
		return nil, fmt.Errorf("payload bytes not found within overlay")
	}
	slice := overlay[idx : idx+len(payload)]
	return append([]byte(nil), slice...), nil
}

func decryptOverlayPayload(overlay []byte, password string, payloadLen int) ([]byte, error) {
	if payloadLen <= 0 {
		return nil, fmt.Errorf("invalid payload length: %d", payloadLen)
	}
	ctLen := payloadLen + 28 // AES-GCM nonce (12) + tag (16)
	if len(overlay) < ctLen {
		return nil, fmt.Errorf("overlay too small (%d) for ciphertext (%d)", len(overlay), ctLen)
	}
	pwdBytes := []byte(password)
	for start := 0; start+ctLen <= len(overlay); start++ {
		window := overlay[start : start+ctLen]
		dec, err := common.DecryptAES256GCM(window, pwdBytes)
		if err == nil {
			if len(dec) != payloadLen {
				return nil, fmt.Errorf("unexpected decrypted length: %d != %d", len(dec), payloadLen)
			}
			return dec, nil
		}
	}
	return nil, fmt.Errorf("no decryptable payload found in overlay")
}

func TestOverlayELF_RoundTrip_Linux(t *testing.T) {
	host := buildNativeELF(t, "host_elf")
	payload := buildNativeELF(t, "payload_elf")

	res := elfrw.OverlayELF(host, payload, "")
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}

	overlay := extractELFOverlayData(t, host)
	pbytes, err := os.ReadFile(payload)
	if err != nil {
		t.Fatalf("read payload failed: %v", err)
	}
	extracted, err := locateOverlayPayload(overlay, pbytes)
	if err != nil {
		t.Fatalf("locate overlay payload failed: %v", err)
	}
	if !bytes.Equal(extracted, pbytes) {
		t.Fatalf("extracted payload mismatch: %d vs %d", len(extracted), len(pbytes))
	}
}

func TestOverlayELF_RoundTrip_Encrypted_Linux(t *testing.T) {
	host := buildNativeELF(t, "host_elf_enc")
	payload := buildNativeELF(t, "payload_elf_enc")
	password := "secret123"

	res := elfrw.OverlayELF(host, payload, password)
	if res == nil || !res.Applied {
		t.Fatalf("expected overlay applied, got %#v", res)
	}

	overlay := extractELFOverlayData(t, host)
	pbytes, err := os.ReadFile(payload)
	if err != nil {
		t.Fatalf("read payload failed: %v", err)
	}
	decrypted, err := decryptOverlayPayload(overlay, password, len(pbytes))
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, pbytes) {
		t.Fatalf("decrypted payload mismatch: got %d bytes", len(decrypted))
	}
}
