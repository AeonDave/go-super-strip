package test

import (
	"os"
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

	result := elfrw.StripELF(elfPath, false)
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

func TestCompactELF_SafeOperation(t *testing.T) {
	elfPath := copyELFFixture(t, "simple_c")

	result := elfrw.CompactELF(elfPath, false, false, true)
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

	result := elfrw.CompactELF(elfPath, true, false, true)
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
