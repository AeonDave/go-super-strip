package main

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"testing"

	"gosstrip/elfrw"
)

// Constants for ELF structures
const (
	elfHeaderSize     = 64
	sectionHeaderSize = 64
	programHeaderSize = 56
	shtProgbits       = 1
	shtStrtab         = 3
	shfAlloc          = 0x2
	shfExecinstr      = 0x4
	shfWrite          = 0x1
	ptLoad            = 1
	pfRead            = 0x4
	pfExecute         = 0x1
	elf64SymSize      = 24
)

// Helper: Create st_info from binding and type
func elf64STInfo(bind, typ uint8) uint8 {
	return (bind << 4) + (typ & 0xf)
}

// Helper: Extract null-terminated string from byte slice
func extractNullTerminatedString(data []byte, offset int) string {
	end := bytes.IndexByte(data[offset:], 0)
	if end == -1 {
		return ""
	}
	return string(data[offset : offset+end])
}

// Test stripping all metadata
func TestELFStripAllMetadata(t *testing.T) {
	elf := &elfrw.ELFFile{
		RawData: make([]byte, 4096),
		Is64Bit: true,
		Sections: []elfrw.Section{
			{Name: ".debug", Offset: 100, Size: 10},
			{Name: ".strtab", Offset: 200, Size: 10},
		},
	}
	copy(elf.RawData[100:110], []byte("debugdata"))
	copy(elf.RawData[200:210], []byte("strtabdat"))

	if err := elf.StripAllMetadata(); err != nil {
		t.Fatalf("StripAllMetadata failed: %v", err)
	}

	for _, sec := range elf.Sections {
		if sec.Size > 0 {
			data, _ := elf.ReadBytes(sec.Offset, int(sec.Size))
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Errorf("Section %s not zeroed", sec.Name)
			}
		}
	}
}

// Test randomizing section names
func TestELFRandomizeSectionNames(t *testing.T) {
	elf := &elfrw.ELFFile{
		Is64Bit: true,
		Sections: []elfrw.Section{
			{Name: ".text"}, {Name: ".data"}, {Name: ".shstrtab"},
		},
	}
	elf.RawData = make([]byte, 1024)
	copy(elf.RawData, []byte{0x7f, 'E', 'L', 'F'})

	if err := elf.RandomizeSectionNames(); err != nil {
		t.Fatalf("RandomizeSectionNames failed: %v", err)
	}

	for _, sec := range elf.Sections {
		if !regexp.MustCompile(`^\.s\d+$`).MatchString(sec.Name) {
			t.Errorf("Section name '%s' not randomized correctly", sec.Name)
		}
	}
}

// Test obfuscating base addresses
func TestELFObfuscateBaseAddresses(t *testing.T) {
	elf := &elfrw.ELFFile{
		Is64Bit: true,
		Segments: []elfrw.Segment{
			{Offset: 0x1000, Size: 0x200, Flags: pfRead | pfExecute},
			{Offset: 0x2000, Size: 0x100, Flags: pfRead | shfWrite},
		},
	}
	elf.RawData = make([]byte, 4096)
	binary.LittleEndian.PutUint64(elf.RawData[24:32], 0x401000)

	if err := elf.ObfuscateBaseAddresses(); err != nil {
		t.Fatalf("ObfuscateBaseAddresses failed: %v", err)
	}

	newEntry := binary.LittleEndian.Uint64(elf.RawData[24:32])
	if newEntry%0x1000 != 0 {
		t.Errorf("New entry point %x not aligned to 0x1000", newEntry)
	}
}

// Test obfuscating exported functions
func TestELFObfuscateExportedFunctions(t *testing.T) {
	elf := &elfrw.ELFFile{
		Is64Bit: true,
		Sections: []elfrw.Section{
			{Name: ".dynstr", Offset: 0x100, Size: 0x50},
			{Name: ".dynsym", Offset: 0x200, Size: 0x60},
		},
	}
	elf.RawData = make([]byte, 512)
	copy(elf.RawData[0x100:], []byte("\x00func1\x00func2\x00"))
	copy(elf.RawData[0x200:], make([]byte, elf64SymSize*3))

	if err := elf.ObfuscateExportedFunctions(); err != nil {
		t.Fatalf("ObfuscateExportedFunctions failed: %v", err)
	}

	dynstr := elf.RawData[0x100:0x150]
	if !bytes.Contains(dynstr, []byte("func1")) {
		t.Errorf("Original function name 'func1' not obfuscated")
	}
}
