package test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"gosstrip/common"
	"gosstrip/elfrw"
)

func TestOverlayELF_AppendsDataString(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	randomBytes, err := common.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("failed to generate overlay data: %v", err)
	}
	overlay := hex.EncodeToString(randomBytes)

	result := elfrw.OverlayELF(elfPath, overlay, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply, got: %#v", result)
	}

	raw, err := elfrw.ExtractOverlay(elfPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	if !bytes.Equal(raw, []byte(overlay)) {
		t.Fatalf("expected overlay payload %q, got %x", overlay, raw)
	}
}

func TestOverlayELF_EmptyDataSkipped(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := elfrw.OverlayELF(elfPath, "", "")
	if result == nil {
		t.Fatal("expected result from OverlayELF, got nil")
	}
	if result.Applied {
		t.Fatalf("expected overlay operation to be skipped, got: %#v", result)
	}
	if result.Message != "Overlay content is empty" {
		t.Fatalf("unexpected skip message: %q", result.Message)
	}
}

func TestOverlayELF_AppendsFileContents(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	payload := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00}
	overlayFile := filepath.Join(t.TempDir(), "overlay.bin")
	if err := os.WriteFile(overlayFile, payload, 0o600); err != nil {
		t.Fatalf("failed to create overlay file: %v", err)
	}

	result := elfrw.OverlayELF(elfPath, overlayFile, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply, got: %#v", result)
	}

	raw, err := elfrw.ExtractOverlay(elfPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	if !bytes.Equal(raw, payload) {
		t.Fatalf("expected overlay payload %x, got %x", payload, raw)
	}
}

func TestOverlayELF_HexLiteral(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")
	payload := "0xA1B2C3D4"
	expected, err := hex.DecodeString(payload[2:])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	result := elfrw.OverlayELF(elfPath, payload, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply, got: %#v", result)
	}
	raw, err := elfrw.ExtractOverlay(elfPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("expected overlay %x, got %x", expected, raw)
	}
}

func TestOverlayELF_EncryptedString(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")
	payload := "elf-overlay"
	password := "password123"

	result := elfrw.OverlayELF(elfPath, payload, password)
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply, got: %#v", result)
	}

	raw, err := elfrw.ExtractOverlay(elfPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	recovered, err := common.ProcessExtractedData(raw, password)
	if err != nil {
		t.Fatalf("failed to decrypt overlay: %v", err)
	}
	if !bytes.Equal(recovered, []byte(payload)) {
		t.Fatalf("expected recovered payload %q, got %q", payload, recovered)
	}
}

func TestOverlayELF_ExtractHexPayload(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")
	payload := "0x1234ABCD"
	expected, err := hex.DecodeString(payload[2:])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	requireApplied(t, "overlay", elfrw.OverlayELF(elfPath, payload, ""))

	raw, err := elfrw.ExtractOverlay(elfPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatalf("expected overlay %x, got %x", expected, raw)
	}
}

func TestOverlayELF_ExtractEncryptedFilePayload(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")
	payload := []byte{0x99, 0x88, 0x77, 0x66}
	filePath := filepath.Join(t.TempDir(), "overlay.bin")
	if err := os.WriteFile(filePath, payload, 0o600); err != nil {
		t.Fatalf("failed to write overlay file: %v", err)
	}
	password := "encpass"
	requireApplied(t, "overlay", elfrw.OverlayELF(elfPath, filePath, password))

	raw, err := elfrw.ExtractOverlay(elfPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	recovered, err := common.ProcessExtractedData(raw, password)
	if err != nil {
		t.Fatalf("failed to decrypt overlay: %v", err)
	}
	if !bytes.Equal(recovered, payload) {
		t.Fatalf("expected payload %x, got %x", payload, recovered)
	}
}
