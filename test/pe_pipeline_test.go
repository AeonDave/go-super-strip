package test

import (
	"bytes"
	"os"
	"testing"

	"gosstrip/common"
	"gosstrip/pack"
	"gosstrip/perw"
)

func TestPEPipelineOperations(t *testing.T) {
	pePath := buildGoFixture(t, "windows", "simple.exe")

	file, err := os.Open(pePath)
	if err != nil {
		t.Fatalf("failed to open PE: %v", err)
	}
	peFile, err := perw.ReadPE(file)
	if err != nil {
		t.Fatalf("ReadPE returned error: %v", err)
	}
	if err := peFile.Close(); err != nil {
		t.Fatalf("failed to close PE file handle: %v", err)
	}

	if err := perw.AnalyzePE(pePath); err != nil {
		t.Fatalf("AnalyzePE returned error: %v", err)
	}

	stripResult := perw.StripPE(pePath, false)
	if stripResult == nil || !stripResult.Applied {
		t.Fatalf("expected StripPE to apply, got %#v", stripResult)
	}

	compactResult := perw.CompactPE(pePath, false)
	if compactResult == nil {
		t.Fatalf("expected CompactPE result, got nil")
	}

	obfResult := perw.ObfuscatePE(pePath, false)
	if obfResult == nil || !obfResult.Applied {
		t.Fatalf("expected ObfuscatePE to apply, got %#v", obfResult)
	}

	marker := "PEIntegrationMarker456"
	sectionName := common.SanitizeSectionName(".integ")
	insertResult := perw.InsertPE(pePath, sectionName, marker, "")
	if insertResult == nil || !insertResult.Applied {
		t.Fatalf("expected InsertPE to apply, got %#v", insertResult)
	}
	afterInsert, err := os.ReadFile(pePath)
	if err != nil {
		t.Fatalf("failed to read PE after insert: %v", err)
	}
	if !bytes.Contains(afterInsert, []byte(marker)) {
		t.Fatalf("expected inserted marker %q to be present", marker)
	}

	regexResult := perw.RegexPE(pePath, marker)
	if regexResult == nil || !regexResult.Applied || regexResult.Count == 0 {
		t.Fatalf("expected RegexPE to remove marker, got %#v", regexResult)
	}
	afterRegex, err := os.ReadFile(pePath)
	if err != nil {
		t.Fatalf("failed to read PE after regex: %v", err)
	}
	if bytes.Contains(afterRegex, []byte(marker)) {
		t.Fatalf("expected marker %q to be removed after regex", marker)
	}

	restore := pack.SetStubCompilerForTests(func(*pack.PackConfig, *pack.PayloadMetadata, []byte) ([]byte, error) {
		return append([]byte("stub"), []byte("pe")...), nil
	})
	defer restore()

	if err := pack.Pack(pePath, "compression=none,encryption=none,polymorphic=false,padding=false"); err != nil {
		t.Fatalf("pack.Pack failed: %v", err)
	}

	packedPath := pePath + ".packed.exe"
	packedData, err := os.ReadFile(packedPath)
	if err != nil {
		t.Fatalf("expected packed PE at %s: %v", packedPath, err)
	}
	if !bytes.HasPrefix(packedData, []byte("stubpe")) {
		t.Fatalf("unexpected packed stub contents: %q", packedData)
	}
}
