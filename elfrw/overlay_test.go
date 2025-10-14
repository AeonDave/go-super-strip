package elfrw

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"gosstrip/common"
)

func TestOverlayELF_AppendsData(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	randomBytes, err := common.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("failed to generate overlay data: %v", err)
	}
	overlay := hex.EncodeToString(randomBytes)

	result := OverlayELF(elfPath, overlay, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply, got: %#v", result)
	}

	updated, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("failed to read modified ELF: %v", err)
	}

	if !bytes.HasSuffix(updated, []byte(overlay)) {
		t.Fatalf("expected file to end with overlay data %q", overlay)
	}
}

func TestOverlayELF_EmptyDataSkipped(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := OverlayELF(elfPath, "", "")
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

	result := OverlayELF(elfPath, overlayFile, "")
	if result == nil || !result.Applied {
		t.Fatalf("expected overlay operation to apply, got: %#v", result)
	}

	updated, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("failed to read modified ELF: %v", err)
	}

	if !bytes.HasSuffix(updated, payload) {
		t.Fatalf("expected file to end with overlay payload %x", payload)
	}
}
