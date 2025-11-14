package test

import (
	"bytes"
	"os"
	"runtime"
	"testing"

	"gosstrip/common"
	"gosstrip/elfrw"
	"gosstrip/pack"
)

func TestELFPipelineOperations(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("ELF pipeline tests require Linux; got %s", runtime.GOOS)
	}

	elfPath := buildGoFixture(t, "linux", "simple")

	file, err := os.Open(elfPath)
	if err != nil {
		t.Fatalf("failed to open ELF: %v", err)
	}
	elfFile, err := elfrw.ReadELF(file)
	if err != nil {
		t.Fatalf("ReadELF returned error: %v", err)
	}
	if err := elfFile.Close(); err != nil {
		t.Fatalf("failed to close ELF file handle: %v", err)
	}

	if err := elfrw.AnalyzeELF(elfPath); err != nil {
		t.Fatalf("AnalyzeELF returned error: %v", err)
	}

	stripResult := elfrw.StripELF(elfPath, false)
	if stripResult == nil || !stripResult.Applied {
		t.Fatalf("expected StripELF to apply, got %#v", stripResult)
	}

	compactResult := elfrw.CompactELF(elfPath, false)
	if compactResult == nil {
		t.Fatalf("expected CompactELF result, got nil")
	}

	obfResult := elfrw.ObfuscateELF(elfPath, true)
	if obfResult == nil || !obfResult.Applied {
		t.Fatalf("expected ObfuscateELF to apply, got %#v", obfResult)
	}

	marker := "ELFIntegrationMarker123"
	sectionName := common.SanitizeSectionName(".integ")
	insertResult := elfrw.InsertELF(elfPath, sectionName, marker, "")
	if insertResult == nil || !insertResult.Applied {
		t.Fatalf("expected InsertELF to apply, got %#v", insertResult)
	}
	afterInsert, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("failed to read ELF after insert: %v", err)
	}
	if !bytes.Contains(afterInsert, []byte(marker)) {
		t.Fatalf("expected inserted marker %q to be present", marker)
	}

	regexResult := elfrw.RegexELF(elfPath, marker)
	if regexResult == nil || !regexResult.Applied || regexResult.Count == 0 {
		t.Fatalf("expected RegexELF to remove marker, got %#v", regexResult)
	}
	afterRegex, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("failed to read ELF after regex: %v", err)
	}
	if bytes.Contains(afterRegex, []byte(marker)) {
		t.Fatalf("expected marker %q to be removed after regex", marker)
	}

	restore := pack.SetStubCompilerForTests(func(*pack.PackConfig, *pack.PayloadMetadata, []byte) ([]byte, error) {
		return append([]byte("stub"), []byte("elf")...), nil
	})
	defer restore()

	if err := pack.Pack(elfPath, "compression=none,encryption=none,polymorphic=false,padding=false"); err != nil {
		t.Fatalf("pack.Pack failed: %v", err)
	}

	packedPath := elfPath + ".packed"
	packedData, err := os.ReadFile(packedPath)
	if err != nil {
		t.Fatalf("expected packed ELF at %s: %v", packedPath, err)
	}
	if !bytes.HasPrefix(packedData, []byte("stubelf")) {
		t.Fatalf("unexpected packed stub contents: %q", packedData)
	}
}
