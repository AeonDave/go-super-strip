package perw

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"gosstrip/common"
)

func TestAnalyzePE_Succeeds(t *testing.T) {
	pePath := copyPEFixture(t, "simple.exe")
	if err := AnalyzePE(pePath); err != nil {
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
	result := CompactPE(pePath, false)
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
