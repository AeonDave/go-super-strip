package perw

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"gosstrip/common"
)

func TestOverlayPE_AppendsData(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")

	randomBytes, err := common.GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("failed to generate overlay data: %v", err)
	}
	overlayString := hex.EncodeToString(randomBytes)

	result := OverlayPE(tempPath, overlayString, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply successfully, got result: %#v", result)
	}

	updated, err := os.ReadFile(tempPath)
	if err != nil {
		t.Fatalf("failed to read modified file: %v", err)
	}

	if !bytes.HasSuffix(updated, []byte(overlayString)) {
		t.Fatalf("expected file to end with overlay data %q", overlayString)
	}
}

func TestOverlayPE_EmptyDataSkipped(t *testing.T) {
	tempPath := copyPEFixture(t, "simple.exe")

	result := OverlayPE(tempPath, "", "")
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

	result := OverlayPE(tempPath, overlayFile, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply successfully, got: %#v", result)
	}

	updated, err := os.ReadFile(tempPath)
	if err != nil {
		t.Fatalf("failed to read modified file: %v", err)
	}

	if !bytes.HasSuffix(updated, payload) {
		t.Fatalf("expected file to end with overlay payload %x", payload)
	}
}
