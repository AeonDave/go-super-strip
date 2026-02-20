package test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"gosstrip/common"
	"gosstrip/perw"
)

func TestOverlayPE_AppendsData(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")

	randomBytes, err := common.GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("failed to generate overlay data: %v", err)
	}
	overlayString := hex.EncodeToString(randomBytes)

	result := perw.OverlayPE(tempPath, overlayString, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply successfully, got result: %#v", result)
	}

	extracted, err := perw.ExtractOverlay(tempPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	if !bytes.Equal(extracted, []byte(overlayString)) {
		t.Fatalf("expected extracted overlay %q, got %q", overlayString, extracted)
	}
}

func TestOverlayPE_EmptyDataSkipped(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")

	result := perw.OverlayPE(tempPath, "", "")
	if result == nil {
		t.Fatal("expected result from OverlayPE, got nil")
	}
	if result.Applied {
		t.Fatalf("expected overlay operation to be skipped, got: %#v", result)
	}
	if result.Message != "Overlay content is empty" {
		t.Fatalf("unexpected skip message: %q", result.Message)
	}
}

func TestOverlayPE_AppendsFileContents(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")

	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x42}
	overlayFile := filepath.Join(t.TempDir(), "overlay.bin")
	if err := os.WriteFile(overlayFile, payload, 0o600); err != nil {
		t.Fatalf("failed to create overlay file: %v", err)
	}

	result := perw.OverlayPE(tempPath, overlayFile, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply successfully, got: %#v", result)
	}

	extracted, err := perw.ExtractOverlay(tempPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	if !bytes.Equal(extracted, payload) {
		t.Fatalf("expected extracted overlay %x, got %x", payload, extracted)
	}
}

func TestOverlayPE_AcceptsHexLiteral(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")
	payload := "0xDEADBEEFCAFEBABE"
	expected, err := hex.DecodeString(payload[2:])
	if err != nil {
		t.Fatalf("failed to decode expected payload: %v", err)
	}

	result := perw.OverlayPE(tempPath, payload, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply, got: %#v", result)
	}

	extracted, err := perw.ExtractOverlay(tempPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	if !bytes.Equal(extracted, expected) {
		t.Fatalf("expected extracted overlay %x, got %x", expected, extracted)
	}
}

func TestOverlayPE_AppendsEncryptedString(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")
	payload := "overlay-config"
	password := "pass123"

	result := perw.OverlayPE(tempPath, payload, password)
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply, got: %#v", result)
	}

	extracted, err := perw.ExtractOverlay(tempPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	recovered, err := common.ProcessExtractedData(extracted, password)
	if err != nil {
		t.Fatalf("failed to decrypt overlay: %v", err)
	}
	if !bytes.Equal(recovered, []byte(payload)) {
		t.Fatalf("expected recovered payload %q, got %q", payload, recovered)
	}
}

func TestOverlayPE_ExtractHexPayload(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")
	payload := "0xABCD0123"
	expected, err := hex.DecodeString(payload[2:])
	if err != nil {
		t.Fatalf("failed to decode expected payload: %v", err)
	}
	requireApplied(t, "overlay", perw.OverlayPE(tempPath, payload, ""))

	extracted, err := perw.ExtractOverlay(tempPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	if !bytes.Equal(extracted, expected) {
		t.Fatalf("expected overlay %x, got %x", expected, extracted)
	}
}

func TestOverlayPE_ExtractEncryptedFilePayload(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	filePath := filepath.Join(t.TempDir(), "overlay.bin")
	if err := os.WriteFile(filePath, payload, 0o600); err != nil {
		t.Fatalf("failed to write overlay file: %v", err)
	}
	password := "filepass"
	requireApplied(t, "overlay", perw.OverlayPE(tempPath, filePath, password))

	extracted, err := perw.ExtractOverlay(tempPath)
	if err != nil {
		t.Fatalf("failed to extract overlay: %v", err)
	}
	recovered, err := common.ProcessExtractedData(extracted, password)
	if err != nil {
		t.Fatalf("failed to decrypt overlay: %v", err)
	}
	if !bytes.Equal(recovered, payload) {
		t.Fatalf("expected recovered payload %x, got %x", payload, recovered)
	}
}

func fileSizePE(t *testing.T, path string) int {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat %s: %v", path, err)
	}
	return int(info.Size())
}
