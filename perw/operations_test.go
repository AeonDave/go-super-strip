package perw

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"gosstrip/common"
)

func hasPESection(t *testing.T, path, name string) bool {
	t.Helper()
	peFile, err := readPe(path, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
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
	coffOffset := int(elfanew) + PE_SIGNATURE_SIZE
	offset := coffOffset + PE_TIMESTAMP_OFFSET
	if offset+4 > len(data) {
		t.Fatalf("timestamp offset out of range for %s", path)
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}

func TestAnalyzePE_Succeeds(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	if _, err := AnalyzePE(pePath, common.DefaultAnalysisOptions()); err != nil {
		t.Fatalf("AnalyzePE returned error: %v", err)
	}
}

func TestStripPE_PreservesPEValidity(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	origStat, err := os.Stat(pePath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	result := StripPE(pePath, false)
	if result == nil {
		t.Fatal("expected result from StripPE, got nil")
	}

	isPE, err := IsPEFile(pePath)
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
	result := ObfuscatePE(pePath, false)
	if result == nil {
		t.Fatal("expected result from ObfuscatePE, got nil")
	}
	if !result.Applied {
		t.Fatalf("expected obfuscation to apply, message: %s", result.Message)
	}

	isPE, err := IsPEFile(pePath)
	if err != nil {
		t.Fatalf("IsPEFile failed: %v", err)
	}
	if !isPE {
		t.Fatal("file is no longer a valid PE after obfuscation")
	}
}

func TestCompactPE_SafeOperation(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	result := CompactPE(pePath, false, false, true)
	if result == nil {
		t.Fatal("expected result from CompactPE, got nil")
	}

	isPE, err := IsPEFile(pePath)
	if err != nil {
		t.Fatalf("IsPEFile failed: %v", err)
	}
	if !isPE {
		t.Fatal("file is no longer a valid PE after compaction")
	}
}

func TestCompactPE_FillModesAndForce(t *testing.T) {
	cfgs := []struct {
		name       string
		force      bool
		fillRandom bool
	}{
		{"zero", false, false},
		{"random", false, true},
		{"forceRandom", true, true},
	}
	for _, cfg := range cfgs {
		t.Run(cfg.name, func(t *testing.T) {
			pePath := copyPEFixture(t, "simple.exe")
			result := CompactPE(pePath, cfg.force, cfg.fillRandom, true)
			if result == nil {
				t.Fatal("expected compact result, got nil")
			}
			isPE, err := IsPEFile(pePath)
			if err != nil {
				t.Fatalf("IsPEFile failed: %v", err)
			}
			if !isPE {
				t.Fatalf("PE invalid after compact fill=%v force=%v", cfg.fillRandom, cfg.force)
			}
		})
	}
}

func TestCompactPE_PreservesTimestamp(t *testing.T) {
	pePath := copyPEFixture(t, "simple_timestamp.exe")
	original := readPETimestamp(t, pePath)

	if result := CompactPE(pePath, false, false, true); result == nil {
		t.Fatal("expected compact result, got nil")
	}
	if got := readPETimestamp(t, pePath); got != original {
		t.Fatalf("expected timestamp %d, got %d", original, got)
	}
}

func TestCompactPE_PreservesTimestampAfterStrip(t *testing.T) {
	pePath := copyPEFixture(t, "simple_strip_timestamp.exe")
	if result := StripPE(pePath, false); result == nil || !result.Applied {
		t.Fatalf("strip failed: %#v", result)
	}
	original := readPETimestamp(t, pePath)
	if original != 0 {
		t.Fatalf("expected strip to zero timestamp, got %d", original)
	}
	if result := CompactPE(pePath, true, false, true); result == nil {
		t.Fatal("compact failed")
	}
	if got := readPETimestamp(t, pePath); got != original {
		t.Fatalf("expected timestamp %d after compact, got %d", original, got)
	}
}

func TestCompactPE_KeepResourcesOption(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	secName := common.SanitizeSectionName(".rsrc")
	if res := InsertPE(pePath, secName, "RESOURCEPAYLOAD", ""); res == nil || !res.Applied {
		t.Fatalf("failed to seed resource section: %#v", res)
	}
	if !hasPESection(t, pePath, ".rsrc") {
		t.Skip("fixture lacks .rsrc even after insertion; skipping test")
	}
	if result := CompactPE(pePath, false, false, true); result == nil {
		t.Fatalf("compact with keepResources failed")
	}
	if !hasPESection(t, pePath, ".rsrc") {
		t.Fatalf(".rsrc should be preserved when keepResources is true")
	}
	if result := CompactPE(pePath, true, false, false); result == nil {
		t.Fatalf("compact without keepResources failed")
	}
	if hasPESection(t, pePath, ".rsrc") {
		t.Fatalf(".rsrc should be removed when keepResources is false and force=true")
	}
}

func TestCompactPE_PreservesImportsWhenNotForced(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	if result := CompactPE(pePath, false, false, true); result == nil {
		t.Fatalf("compact failed")
	}
	if !hasPESection(t, pePath, ".idata") {
		t.Fatalf(".idata should remain when force=false")
	}
	if result := CompactPE(pePath, true, false, true); result == nil {
		t.Fatalf("forced compact failed")
	}
	if hasPESection(t, pePath, ".idata") {
		t.Fatalf(".idata should be removable when force=true")
	}
}

func TestInsertPE_AddsSection(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	sectionName := common.SanitizeSectionName(".custom")

	result := InsertPE(pePath, sectionName, "HelloWorld", "")
	if result == nil {
		t.Fatal("expected result from InsertPE, got nil")
	}
	if !result.Applied {
		t.Fatalf("expected insert to apply, message: %s", result.Message)
	}

	peFile, err := readPe(pePath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to reopen PE: %v", err)
	}
	defer func() {
		_ = peFile.Close()
	}()

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

	result := RegexPE(pePath, "[")
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

	insertResult := InsertPE(pePath, sectionName, marker, "")
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

	regexResult := RegexPE(pePath, marker)
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

func TestStripPE_RemovesUPXMarkers(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	sectionName := common.SanitizeSectionName(".upx")
	upxBanner := "UPX! Info: This file is packed with the UPX executable packer http://upx.sf.net $"

	insertResult := InsertPE(pePath, sectionName, upxBanner, "")
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

	stripResult := StripPE(pePath, false)
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
