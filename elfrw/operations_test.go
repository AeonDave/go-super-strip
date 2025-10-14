package elfrw

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"gosstrip/common"
)

func TestAnalyzeELF_Succeeds(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	if err := AnalyzeELF(elfPath); err != nil {
		t.Fatalf("AnalyzeELF returned error: %v", err)
	}
}

func TestStripELF_PreservesELFValidity(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	origStat, err := os.Stat(elfPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	result := StripELF(elfPath, false)
	if result == nil {
		t.Fatal("expected result from StripELF, got nil")
	}

	isELF, err := IsELFFile(elfPath)
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

func TestCompactELF_SafeOperation(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := CompactELF(elfPath, false)
	if result == nil {
		t.Fatal("expected result from CompactELF, got nil")
	}

	isELF, err := IsELFFile(elfPath)
	if err != nil {
		t.Fatalf("IsELFFile failed: %v", err)
	}
	if !isELF {
		t.Fatal("file is no longer recognized as ELF after compaction")
	}
}

func TestObfuscateELF_AppliesChanges(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := ObfuscateELF(elfPath, true)
	if result == nil {
		t.Fatal("expected result from ObfuscateELF, got nil")
	}
	if !result.Applied {
		t.Fatalf("expected obfuscation to apply, message: %s", result.Message)
	}
}

func TestInsertELF_AddsSection(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")
	sectionName := common.SanitizeSectionName(".custom")

	result := InsertELF(elfPath, sectionName, "HelloELF", "")
	if result == nil {
		t.Fatal("expected result from InsertELF, got nil")
	}
	if !result.Applied {
		t.Fatalf("expected insert to apply, message: %s", result.Message)
	}

	elfFile, err := readElf(elfPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to reopen ELF: %v", err)
	}
	defer func() {
		_ = elfFile.Close()
	}()

	found := false
	for _, sec := range elfFile.Sections {
		if sec.Name == sectionName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find inserted section %q", sectionName)
	}
}

func TestRegexELF_InvalidPattern(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := RegexELF(elfPath, "[")
	if result == nil {
		t.Fatal("expected result from RegexELF, got nil")
	}
	if result.Applied {
		t.Fatalf("expected regex operation to be skipped, got: %#v", result)
	}
	if !strings.Contains(result.Message, "invalid regex") {
		t.Fatalf("unexpected message: %q", result.Message)
	}
}

func TestRegexELF_RemovesMatches(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")
	marker := "UniqueELFRegexMarker123"
	sectionName := common.SanitizeSectionName(".regex")

	insertResult := InsertELF(elfPath, sectionName, marker, "")
	if insertResult == nil || !insertResult.Applied {
		t.Fatalf("expected insert operation to apply: %#v", insertResult)
	}

	data, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("failed to read ELF after insert: %v", err)
	}
	if !bytes.Contains(data, []byte(marker)) {
		t.Fatalf("expected inserted marker %q to be present", marker)
	}

	regexResult := RegexELF(elfPath, marker)
	if regexResult == nil {
		t.Fatal("expected result from RegexELF, got nil")
	}
	if !regexResult.Applied || regexResult.Count == 0 {
		t.Fatalf("expected regex operation to apply with matches, got: %#v", regexResult)
	}

	updated, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("failed to read ELF after regex: %v", err)
	}
	if bytes.Contains(updated, []byte(marker)) {
		t.Fatalf("expected marker %q to be removed after regex", marker)
	}
}

func TestStripELF_RemovesUPXMarkers(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")
	sectionName := common.SanitizeSectionName(".upx")
	upxBanner := "UPX! Info: This file is packed with the UPX executable packer http://upx.sf.net $"

	insertResult := InsertELF(elfPath, sectionName, upxBanner, "")
	if insertResult == nil || !insertResult.Applied {
		t.Fatalf("expected insert operation to apply: %#v", insertResult)
	}

	dataBefore, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("failed to read ELF after insert: %v", err)
	}
	if !bytes.Contains(dataBefore, []byte("UPX!")) {
		t.Fatalf("expected UPX marker to be present before stripping")
	}
	if !bytes.Contains(dataBefore, []byte("Info: This file is packed")) {
		t.Fatalf("expected UPX banner to be present before stripping")
	}

	stripResult := StripELF(elfPath, false)
	if stripResult == nil {
		t.Fatal("expected result from StripELF, got nil")
	}
	if !stripResult.Applied {
		t.Fatalf("expected strip operation to apply, message: %s", stripResult.Message)
	}

	dataAfter, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("failed to read ELF after strip: %v", err)
	}
	if bytes.Contains(dataAfter, []byte("UPX!")) {
		t.Fatalf("expected UPX marker to be removed after stripping")
	}
	if bytes.Contains(dataAfter, []byte("Info: This file is packed")) {
		t.Fatalf("expected UPX banner to be removed after stripping")
	}
}
