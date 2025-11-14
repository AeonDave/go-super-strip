package test

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"gosstrip/elfrw"
	"gosstrip/perw"
)

func TestReadELFWithNativeParser(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("ELF reader test requires Linux; got %s", runtime.GOOS)
	}

	elfPath := buildGoFixture(t, "linux", "native_reader")

	file, err := os.Open(elfPath)
	if err != nil {
		t.Fatalf("failed to open ELF fixture: %v", err)
	}
	elfFile, err := elfrw.ReadELF(file)
	if err != nil {
		_ = file.Close()
		t.Fatalf("ReadELF failed: %v", err)
	}
	defer func() { _ = elfFile.Close() }()

	if len(elfFile.Sections) == 0 {
		t.Fatalf("expected ELF sections to be parsed")
	}
	var textSectionFound bool
	for _, section := range elfFile.Sections {
		if section.Name == ".text" {
			textSectionFound = true
			if section.Size == 0 {
				t.Fatalf("expected non-empty .text section")
			}
			break
		}
	}
	if !textSectionFound {
		t.Fatalf("expected .text section in ELF file")
	}
	if len(elfFile.Segments) == 0 {
		t.Fatalf("expected ELF segments to be parsed")
	}
	var loadableSegment bool
	for _, segment := range elfFile.Segments {
		if segment.Loadable {
			loadableSegment = true
			break
		}
	}
	if !loadableSegment {
		t.Fatalf("expected at least one loadable segment")
	}
}

func TestReadPEWithStandardLibrary(t *testing.T) {
	pePath := buildGoFixture(t, "windows", "native_reader.exe")

	file, err := os.Open(pePath)
	if err != nil {
		t.Fatalf("failed to open PE fixture: %v", err)
	}
	peFile, err := perw.ReadPE(file)
	if err != nil {
		_ = file.Close()
		t.Fatalf("ReadPE failed: %v", err)
	}
	defer func() { _ = peFile.Close() }()

	if peFile.PE == nil {
		t.Fatalf("expected native PE metadata to be available")
	}
	if len(peFile.Sections) == 0 {
		t.Fatalf("expected PE sections to be parsed")
	}
	var textSection bool
	for _, section := range peFile.Sections {
		name := strings.ToLower(section.Name)
		if strings.Contains(name, "text") {
			textSection = true
			if section.Size == 0 {
				t.Fatalf("expected non-empty text section")
			}
			break
		}
	}
	if !textSection {
		t.Fatalf("expected text section in PE file")
	}
}
