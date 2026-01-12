package test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gosstrip/common"
	"gosstrip/elfrw"
)

func elfHasSection(t *testing.T, path, name string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
	}
	defer func() { _ = f.Close() }()
	elfFile, err := elfrw.ReadELF(f)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}
	defer func() { _ = elfFile.Close() }()
	target := strings.ToLower(name)
	for _, sec := range elfFile.Sections {
		if strings.ToLower(sec.Name) == target {
			return true
		}
	}
	return false
}

func readELFSectionData(t *testing.T, path, name string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
	}
	defer func() { _ = f.Close() }()
	elfFile, err := elfrw.ReadELF(f)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}
	defer func() { _ = elfFile.Close() }()
	for _, sec := range elfFile.Sections {
		if sec.Name == name {
			start := int(sec.Offset)
			end := start + int(sec.Size)
			if end > len(elfFile.RawData) {
				end = len(elfFile.RawData)
			}
			data := make([]byte, end-start)
			copy(data, elfFile.RawData[start:end])
			return data
		}
	}
	t.Fatalf("section %s not found", name)
	return nil
}

func TestAnalyzeELF_Succeeds(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")
	if _, err := elfrw.AnalyzeELF(elfPath, common.DefaultAnalysisOptions()); err != nil {
		t.Fatalf("AnalyzeELF returned error: %v", err)
	}
}

func TestStripELF_PreservesELFValidity(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	origStat, err := os.Stat(elfPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	result := elfrw.StripELF(elfPath, false, nil)
	if result == nil {
		t.Fatal("expected result from StripELF, got nil")
	}

	isELF, err := elfrw.IsELFFile(elfPath)
	if err != nil {
		t.Fatalf("IsELFFile failed: %v", err)
	}
	if !isELF {
		t.Fatal("file is no longer recognized as ELF after stripping")
	}

	newStat, err := os.Stat(elfPath)
	if err != nil {
		t.Fatalf("stat after strip failed: %v", err)
	}
	if newStat.Size() == 0 {
		t.Fatal("file size is zero after stripping")
	}
	if result.Applied && newStat.Size() > origStat.Size() {
		t.Fatalf("stripped file grew from %d to %d bytes", origStat.Size(), newStat.Size())
	}
}

func TestStripELF_PreservesGoPclnByDefault(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_go_pcln")
	original := readELFSectionData(t, elfPath, ".gopclntab")
	if len(original) == 0 {
		t.Skip("fixture missing .gopclntab; skipping preservation check")
	}

	if res := elfrw.StripELF(elfPath, false, nil); res == nil {
		t.Fatal("expected result from StripELF, got nil")
	}

	after := readELFSectionData(t, elfPath, ".gopclntab")
	if !bytes.Equal(original, after) {
		t.Fatalf(".gopclntab changed after default strip (%d -> %d bytes)", len(original), len(after))
	}
}

func TestCompactELF_SafeOperation(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := elfrw.CompactELF(elfPath, false, true)
	if result == nil {
		t.Fatal("expected result from CompactELF, got nil")
	}

	isELF, err := elfrw.IsELFFile(elfPath)
	if err != nil {
		t.Fatalf("IsELFFile failed: %v", err)
	}
	if !isELF {
		t.Fatal("file is no longer a valid ELF after compaction")
	}
}

func TestCompactELF_ForceRemovesLoaderSections(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := elfrw.CompactELF(elfPath, true, true)
	if result == nil || !result.Applied {
		t.Fatalf("expected force compact to apply: %#v", result)
	}
	if elfHasSection(t, elfPath, ".symtab") {
		t.Fatalf(".symtab should be removable when force=true")
	}
}

func TestInsertELF_AddsSection(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := elfrw.InsertELF(elfPath, ".custom", "HelloWorld", "")
	if result == nil {
		t.Fatal("expected result from InsertELF, got nil")
	}
	if !result.Applied {
		t.Fatalf("expected insert to apply, message: %s", result.Message)
	}

	f, err := os.Open(elfPath)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
	}
	defer func() { _ = f.Close() }()
	elfFile, err := elfrw.ReadELF(f)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}
	defer func() { _ = elfFile.Close() }()
	found := false
	for _, sec := range elfFile.Sections {
		if sec.Name == ".custom" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find inserted section .custom")
	}
}

func TestStripELF_FillOverrideZero(t *testing.T) {
	elfPath := copyELFFixture(t, "fill_zero")
	sectionName := ".note.zero"
	payload := strings.Repeat("Z", 64)
	if res := elfrw.InsertELF(elfPath, sectionName, payload, ""); res == nil || !res.Applied {
		t.Fatalf("failed to insert note section: %#v", res)
	}

	if res := elfrw.StripELF(elfPath, false, boolPointer(false)); res == nil || !res.Applied {
		t.Fatalf("expected strip to apply: %#v", res)
	}
	data := readELFSectionData(t, elfPath, sectionName)
	if !isAllZero(data) {
		t.Fatalf("expected section %s to be zero-filled", sectionName)
	}
}

func TestStripELF_FillOverrideRandom(t *testing.T) {
	elfPath := copyELFFixture(t, "fill_random")
	sectionName := ".note.rand"
	payload := strings.Repeat("R", 64)
	if res := elfrw.InsertELF(elfPath, sectionName, payload, ""); res == nil || !res.Applied {
		t.Fatalf("failed to insert note section: %#v", res)
	}

	if res := elfrw.StripELF(elfPath, false, boolPointer(true)); res == nil || !res.Applied {
		t.Fatalf("expected strip to apply: %#v", res)
	}
	data := readELFSectionData(t, elfPath, sectionName)
	if isAllZero(data) {
		t.Fatalf("expected section %s to be randomized", sectionName)
	}
}

func TestStripELF_RegexPackerUsesRandomFill(t *testing.T) {
	elfPath := copyELFFixture(t, "regex_packer")
	sectionName := ".packupx"
	payload := "5.02 UPX! DEMO"

	requireApplied(t, "insert", elfrw.InsertELF(elfPath, sectionName, payload, ""))

	before := readELFSectionData(t, elfPath, sectionName)
	if !strings.Contains(string(before), "UPX!") {
		t.Fatalf("expected UPX marker to be present before strip")
	}

	res := elfrw.StripELF(elfPath, false, nil)
	requireApplied(t, "strip", res)

	after := readELFSectionData(t, elfPath, sectionName)
	if strings.Contains(string(after), "UPX!") {
		t.Fatalf("expected UPX marker removed after strip")
	}
	if isAllZero(after) {
		t.Fatalf("expected random fill for packer rule, got all zeros")
	}
}

func TestStripELF_PreservesInterpFromRegex(t *testing.T) {
	elfPath := copyELFFixture(t, "strip_interp")
	sectionName := ".interp"
	payload := "/lib64/ld-linux-gosstrip-test.so.2"
	requireApplied(t, "insert", elfrw.InsertELF(elfPath, sectionName, payload, ""))

	before := readELFSectionData(t, elfPath, sectionName)
	if !bytes.Contains(before, []byte("ld-linux-gosstrip-test")) {
		t.Fatalf("expected loader path marker to be present before strip")
	}

	if res := elfrw.StripELF(elfPath, false, nil); res == nil {
		t.Fatalf("expected strip result, got nil")
	}
	after := readELFSectionData(t, elfPath, sectionName)
	if !bytes.Contains(after, []byte("ld-linux-gosstrip-test")) {
		t.Fatalf("expected .interp payload to remain after safe strip")
	}
}

func TestStripELF_PreservesExceptionTableByDefault(t *testing.T) {
	elfPath := copyELFFixture(t, "strip_except")
	sectionName := ".gcc_except_table"
	payload := strings.Repeat("E", 64)
	requireApplied(t, "insert", elfrw.InsertELF(elfPath, sectionName, payload, ""))

	if res := elfrw.StripELF(elfPath, false, nil); res == nil {
		t.Fatalf("expected strip result, got nil")
	}
	data := readELFSectionData(t, elfPath, sectionName)
	if isAllZero(data) {
		t.Fatalf("expected %s to remain in safe strip mode", sectionName)
	}
}

func TestELFExtractSectionByNameAndIndex(t *testing.T) {
	elfPath := copyELFFixture(t, "simple")
	hexSection := common.SanitizeSectionName(".hexsec")
	fileSection := common.SanitizeSectionName(".filesec")

	hexPayload := "0xA1B2C3D4"
	requireApplied(t, "insert", elfrw.InsertELF(elfPath, hexSection, hexPayload, "hexpass"))

	filePayload := []byte{0x01, 0x02, 0x03, 0x04}
	filePath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(filePath, filePayload, 0o600); err != nil {
		t.Fatalf("failed to write payload file: %v", err)
	}
	requireApplied(t, "insert", elfrw.InsertELF(elfPath, fileSection, filePath, "filepass"))

	extractedHex, sectionName, err := elfrw.ExtractSection(elfPath, hexSection, nil, "hexpass")
	if err != nil {
		t.Fatalf("failed to extract ELF section by name: %v", err)
	}
	wantHex, err := hex.DecodeString(hexPayload[2:])
	if err != nil {
		t.Fatalf("failed to decode expected hex payload: %v", err)
	}
	if !bytes.Equal(extractedHex, wantHex) {
		t.Fatalf("expected extracted data %x, got %x", wantHex, extractedHex)
	}
	if sectionName != hexSection {
		t.Fatalf("expected section name %q, got %q", hexSection, sectionName)
	}

	f, err := os.Open(elfPath)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
	}
	elfFile, err := elfrw.ReadELF(f)
	if err != nil {
		t.Fatalf("failed to parse ELF: %v", err)
	}
	lastIndex := len(elfFile.Sections) - 1
	_ = f.Close()
	extractedFile, extractedName, err := elfrw.ExtractSection(elfPath, "", &lastIndex, "filepass")
	if err != nil {
		t.Fatalf("failed to extract ELF section by index: %v", err)
	}
	if extractedName != fileSection {
		t.Fatalf("expected extracted section name %q, got %q", fileSection, extractedName)
	}
	if !bytes.Equal(extractedFile, filePayload) {
		t.Fatalf("expected extracted file payload %x, got %x", filePayload, extractedFile)
	}
}
