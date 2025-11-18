package test

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gosstrip/common"
	"gosstrip/perw"
)

func hasPESection(t *testing.T, path, name string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open PE: %v", err)
	}
	defer func() { _ = f.Close() }()
	peFile, err := perw.ReadPE(f)
	if err != nil {
		t.Fatalf("failed to parse PE: %v", err)
	}
	defer func() { _ = peFile.Close() }()

	target := strings.ToLower(name)
	for _, sec := range peFile.Sections {
		if strings.ToLower(strings.Trim(sec.Name, "\x00")) == target {
			return true
		}
	}
	return false
}

func readPESectionData(t *testing.T, path, name string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
	}
	defer func() { _ = f.Close() }()
	peFile, err := perw.ReadPE(f)
	if err != nil {
		t.Fatalf("failed to parse PE: %v", err)
	}
	defer func() { _ = peFile.Close() }()
	sec, err := peFile.GetSectionByName(name)
	if err != nil {
		t.Fatalf("section %s not found: %v", name, err)
	}
	data, err := peFile.ReadBytes(sec.Offset, int(sec.VirtualSize))
	if err != nil {
		t.Fatalf("failed reading section bytes: %v", err)
	}
	return append([]byte(nil), data...)
}

func readPETimestamp(t *testing.T, path string) uint32 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if len(data) < 0x40 {
		t.Fatalf("file too small: %s", path)
	}
	elfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	coffOffset := int(elfanew) + perw.PE_SIGNATURE_SIZE
	offset := coffOffset + perw.PE_TIMESTAMP_OFFSET
	if offset+4 > len(data) {
		t.Fatalf("timestamp offset out of range for %s", path)
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}

func readPECharacteristics(t *testing.T, path string) uint16 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if len(data) < 0x40 {
		t.Fatalf("file too small: %s", path)
	}
	elfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	coffOffset := int(elfanew) + perw.PE_SIGNATURE_SIZE
	charOffset := coffOffset + perw.PE_CHARACTERISTICS_OFFSET
	if charOffset+2 > len(data) {
		t.Fatalf("characteristics offset out of range for %s", path)
	}
	return binary.LittleEndian.Uint16(data[charOffset : charOffset+2])
}

func readPEDLLCharacteristics(t *testing.T, path string) uint16 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if len(data) < 0x40 {
		t.Fatalf("file too small: %s", path)
	}
	elfanew := binary.LittleEndian.Uint32(data[0x3C:0x40])
	coffOffset := int(elfanew) + perw.PE_SIGNATURE_SIZE
	optionalOffset := coffOffset + perw.PE_FILE_HEADER_SIZE
	if optionalOffset+2 > len(data) {
		t.Fatalf("optional header offset out of range for %s", path)
	}
	magic := binary.LittleEndian.Uint16(data[optionalOffset : optionalOffset+2])
	var dllOffset int
	switch magic {
	case perw.PE32_MAGIC:
		dllOffset = optionalOffset + perw.PE32_DLL_CHARACTERISTICS
	case perw.PE64_MAGIC:
		dllOffset = optionalOffset + perw.PE64_DLL_CHARACTERISTICS
	default:
		t.Fatalf("unknown PE magic 0x%X in %s", magic, path)
	}
	if dllOffset+2 > len(data) {
		t.Fatalf("DLL characteristics offset out of range for %s", path)
	}
	return binary.LittleEndian.Uint16(data[dllOffset : dllOffset+2])
}

func TestAnalyzePE_Succeeds(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	if _, err := perw.AnalyzePE(pePath, common.DefaultAnalysisOptions()); err != nil {
		t.Fatalf("AnalyzePE returned error: %v", err)
	}
}

func TestStripPE_PreservesPEValidity(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	origStat, err := os.Stat(pePath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	result := perw.StripPE(pePath, false, nil)
	if result == nil {
		t.Fatal("expected result from StripPE, got nil")
	}

	isPE, err := perw.IsPEFile(pePath)
	if err != nil {
		t.Fatalf("IsPEFile failed: %v", err)
	}
	if !isPE {
		t.Fatal("file is no longer recognized as PE after stripping")
	}

	newStat, err := os.Stat(pePath)
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

func TestObfuscatePE_AppliesChanges(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	result := perw.ObfuscatePE(pePath, false)
	if result == nil {
		t.Fatal("expected result from ObfuscatePE, got nil")
	}
	if !result.Applied {
		t.Fatalf("expected obfuscation to apply, message: %s", result.Message)
	}

	isPE, err := perw.IsPEFile(pePath)
	if err != nil {
		t.Fatalf("IsPEFile failed: %v", err)
	}
	if !isPE {
		t.Fatal("file is no longer a valid PE after obfuscation")
	}
}

func TestObfuscatePE_PreservesImports(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	res := perw.ObfuscatePE(pePath, true)
	if res == nil || !res.Applied {
		t.Fatalf("expected obfuscation to apply: %#v", res)
	}

	f, err := os.Open(pePath)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
	}
	defer func() { _ = f.Close() }()
	peFile, err := perw.ReadPE(f)
	if err != nil {
		t.Fatalf("failed to parse PE: %v", err)
	}
	defer func() { _ = peFile.Close() }()
	importSyms, _ := peFile.PE.ImportedSymbols()
	if len(importSyms) == 0 {
		t.Fatal("import table was wiped after obfuscation")
	}
}

func TestCompactPE_SafeOperation(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	result := perw.CompactPE(pePath, false, true)
	if result == nil {
		t.Fatal("expected result from CompactPE, got nil")
	}

	isPE, err := perw.IsPEFile(pePath)
	if err != nil {
		t.Fatalf("IsPEFile failed: %v", err)
	}
	if !isPE {
		t.Fatal("file is no longer a valid PE after compaction")
	}
}

func TestCompactPE_PreservesTimestamp(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	before := readPETimestamp(t, pePath)

	result := perw.CompactPE(pePath, false, true)
	if result == nil || !result.Applied {
		t.Fatalf("expected compaction to apply, got %#v", result)
	}

	after := readPETimestamp(t, pePath)
	if before != after {
		t.Fatalf("expected timestamp to remain %08x, got %08x", before, after)
	}
}

func TestCompactPE_ForceRemovesImports(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	result := perw.CompactPE(pePath, true, false)
	if result == nil || !result.Applied {
		t.Fatalf("expected compaction to apply, got %#v", result)
	}
	if hasPESection(t, pePath, ".idata") {
		t.Fatalf(".idata should be removable when force=true")
	}
}

func TestCompactPE_ForceRelocDisablesASLR(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	if !hasPESection(t, pePath, ".reloc") {
		t.Skip("fixture missing .reloc section")
	}
	result := perw.CompactPE(pePath, true, false)
	if result == nil || !result.Applied {
		t.Fatalf("expected compaction to apply, got %#v", result)
	}
	flags := readPECharacteristics(t, pePath)
	if flags&pe.IMAGE_FILE_RELOCS_STRIPPED == 0 {
		t.Fatalf("expected IMAGE_FILE_RELOCS_STRIPPED after removing .reloc, flags=0x%X", flags)
	}
	dllChars := readPEDLLCharacteristics(t, pePath)
	if dllChars&perw.IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE != 0 {
		t.Fatalf("expected DYNAMIC_BASE flag to be cleared, DLL characteristics=0x%X", dllChars)
	}
}

func TestInsertPE_AddsSection(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	sectionName := common.SanitizeSectionName(".custom")

	result := perw.InsertPE(pePath, sectionName, "HelloWorld", "")
	if result == nil {
		t.Fatal("expected result from InsertPE, got nil")
	}
	if !result.Applied {
		t.Fatalf("expected insert to apply, message: %s", result.Message)
	}

	f, err := os.Open(pePath)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
	}
	defer func() { _ = f.Close() }()
	peFile, err := perw.ReadPE(f)
	if err != nil {
		t.Fatalf("failed to parse PE: %v", err)
	}
	defer func() { _ = peFile.Close() }()

	found := false
	for _, sec := range peFile.Sections {
		if sec.Name == sectionName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find inserted section %q", sectionName)
	}
}

func TestRegexPE_InvalidPattern(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")

	result := perw.RegexPE(pePath, nil, []string{"["})
	if result == nil {
		t.Fatal("expected result from RegexPE, got nil")
	}
	if result.Applied {
		t.Fatalf("expected regex operation to be skipped, got: %#v", result)
	}
	if !strings.Contains(result.Message, "invalid regex") {
		t.Fatalf("unexpected message: %q", result.Message)
	}
}

func TestRegexPE_RemovesMatches(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	marker := "UniqueRegexMarker12345"
	sectionName := common.SanitizeSectionName(".regex")

	insertResult := perw.InsertPE(pePath, sectionName, marker, "")
	if insertResult == nil || !insertResult.Applied {
		t.Fatalf("expected insert operation to apply: %#v", insertResult)
	}

	data, err := os.ReadFile(pePath)
	if err != nil {
		t.Fatalf("failed to read PE after insert: %v", err)
	}
	if !bytes.Contains(data, []byte(marker)) {
		t.Fatalf("expected inserted marker %q to be present", marker)
	}

	regexResult := perw.RegexPE(pePath, nil, []string{marker})
	if regexResult == nil {
		t.Fatal("expected result from RegexPE, got nil")
	}
	if !regexResult.Applied || regexResult.Count == 0 {
		t.Fatalf("expected regex operation to apply with matches, got: %#v", regexResult)
	}

	updated, err := os.ReadFile(pePath)
	if err != nil {
		t.Fatalf("failed to read PE after regex: %v", err)
	}
	if bytes.Contains(updated, []byte(marker)) {
		t.Fatalf("expected marker %q to be removed after regex", marker)
	}
}

func TestRegexPE_FillZeroOverride(t *testing.T) {
	pePath := copyPEFixture(t, "regex_fill_zero.exe")
	sectionName := common.SanitizeSectionName(".regexfill0")
	payload := "FillZeroMarker"

	requireApplied(t, "insert", perw.InsertPE(pePath, sectionName, payload, ""))
	res := perw.RegexPE(pePath, boolPointer(false), []string{payload})
	if res == nil || !res.Applied {
		t.Fatalf("expected regex operation to apply: %#v", res)
	}
	data := readPESectionData(t, pePath, sectionName)
	if bytes.Contains(data, []byte(payload)) {
		t.Fatalf("expected payload removed from section")
	}
	if !isAllZero(data) {
		t.Fatalf("expected section to be zero filled, got %x", data[:min(len(data), 8)])
	}
}

func TestRegexPE_FillRandomOverride(t *testing.T) {
	pePath := copyPEFixture(t, "regex_fill_rand.exe")
	sectionName := common.SanitizeSectionName(".regexfill1")
	payload := "FillRandomMarker"

	requireApplied(t, "insert", perw.InsertPE(pePath, sectionName, payload, ""))
	res := perw.RegexPE(pePath, boolPointer(true), []string{payload})
	if res == nil || !res.Applied {
		t.Fatalf("expected regex operation to apply: %#v", res)
	}
	data := readPESectionData(t, pePath, sectionName)
	if bytes.Contains(data, []byte(payload)) {
		t.Fatalf("expected payload removed from section")
	}
	if isAllZero(data) {
		t.Fatalf("expected random fill, got all zeros")
	}
}

func TestStripPE_RemovesUPXMarkers(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	sectionName := common.SanitizeSectionName(".upx")
	upxBanner := "UPX! Info: This file is packed with the UPX executable packer http://upx.sf.net $"

	insertResult := perw.InsertPE(pePath, sectionName, upxBanner, "")
	if insertResult == nil || !insertResult.Applied {
		t.Fatalf("expected insert operation to apply: %#v", insertResult)
	}

	dataBefore, err := os.ReadFile(pePath)
	if err != nil {
		t.Fatalf("failed to read PE after insert: %v", err)
	}
	if !bytes.Contains(dataBefore, []byte("UPX!")) {
		t.Fatalf("expected UPX marker to be present before stripping")
	}
	if !bytes.Contains(dataBefore, []byte("Info: This file is packed")) {
		t.Fatalf("expected UPX banner to be present before stripping")
	}

	stripResult := perw.StripPE(pePath, false, nil)
	if stripResult == nil {
		t.Fatal("expected result from StripPE, got nil")
	}
	if !stripResult.Applied {
		t.Fatalf("expected strip operation to apply, message: %s", stripResult.Message)
	}

	dataAfter, err := os.ReadFile(pePath)
	if err != nil {
		t.Fatalf("failed to read PE after strip: %v", err)
	}
	if bytes.Contains(dataAfter, []byte("UPX!")) {
		t.Fatalf("expected UPX marker to be removed after stripping")
	}
	if bytes.Contains(dataAfter, []byte("Info: This file is packed")) {
		t.Fatalf("expected UPX banner to be removed after stripping")
	}
}

func TestStripPE_FillOverrideZero(t *testing.T) {
	pePath := copyPEFixture(t, "fill_zero.exe")
	sectionName := common.SanitizeSectionName(".debugfill")
	payload := bytes.Repeat([]byte{0xAB}, 128)
	if res := perw.InsertPE(pePath, sectionName, string(payload), ""); res == nil || !res.Applied {
		t.Fatalf("failed to insert test section: %#v", res)
	}

	if res := perw.StripPE(pePath, false, boolPointer(false)); res == nil || !res.Applied {
		t.Fatalf("expected strip to apply: %#v", res)
	}
	data := readPESectionData(t, pePath, sectionName)
	if !isAllZero(data) {
		t.Fatalf("expected section %s to be zero-filled, got %x", sectionName, data[:min(len(data), 8)])
	}
}

func TestStripPE_FillOverrideRandom(t *testing.T) {
	pePath := copyPEFixture(t, "fill_random.exe")
	sectionName := common.SanitizeSectionName(".debugrand")
	payload := bytes.Repeat([]byte{0xCD}, 128)
	if res := perw.InsertPE(pePath, sectionName, string(payload), ""); res == nil || !res.Applied {
		t.Fatalf("failed to insert test section: %#v", res)
	}

	if res := perw.StripPE(pePath, false, boolPointer(true)); res == nil || !res.Applied {
		t.Fatalf("expected strip to apply: %#v", res)
	}
	data := readPESectionData(t, pePath, sectionName)
	if isAllZero(data) {
		t.Fatalf("expected section %s to be randomized, all bytes were zero", sectionName)
	}
}

func TestPEExtractSectionByNameAndIndex(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	hexSection := common.SanitizeSectionName(".hexsec")
	fileSection := common.SanitizeSectionName(".filesec")

	hexPayload := "0xDEADBEEFCAFE"
	requireApplied(t, "insert", perw.InsertPE(pePath, hexSection, hexPayload, "hexpass"))

	filePayload := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	filePath := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(filePath, filePayload, 0o600); err != nil {
		t.Fatalf("failed to write payload file: %v", err)
	}
	requireApplied(t, "insert", perw.InsertPE(pePath, fileSection, filePath, "filepass"))

	extractedHex, sectionName, err := perw.ExtractSection(pePath, hexSection, nil, "hexpass")
	if err != nil {
		t.Fatalf("failed to extract section by name: %v", err)
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

	f, err := os.Open(pePath)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
	}
	peFile, err := perw.ReadPE(f)
	if err != nil {
		t.Fatalf("failed to parse PE: %v", err)
	}
	lastIndex := len(peFile.Sections) - 1
	_ = f.Close()
	extractedFile, extractedName, err := perw.ExtractSection(pePath, "", &lastIndex, "filepass")
	if err != nil {
		t.Fatalf("failed to extract section by index: %v", err)
	}
	if extractedName != fileSection {
		t.Fatalf("expected extracted section name %q, got %q", fileSection, extractedName)
	}
	if !bytes.Equal(extractedFile, filePayload) {
		t.Fatalf("expected extracted file payload %x, got %x", filePayload, extractedFile)
	}
}
