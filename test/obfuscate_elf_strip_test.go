package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"regexp"
	"testing"

	"gosstrip/elfrw"

	"github.com/yalue/elf_reader"
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
	elff := &elfrw.ELFFile{
		RawData: make([]byte, 4096),
		Is64Bit: true,
		Sections: []elfrw.Section{
			{Name: ".debug", Offset: 100, Size: 10},
			{Name: ".strtab", Offset: 200, Size: 10},
		},
	}
	copy(elff.RawData[100:110], []byte("debugdata"))
	copy(elff.RawData[200:210], []byte("strtabdat"))

	if err := elff.StripAllMetadata(false); err != nil {
		t.Fatalf("StripAllMetadata failed: %v", err)
	}

	for _, sec := range elff.Sections {
		if sec.Size > 0 {
			data, _ := elff.ReadBytes(sec.Offset, int(sec.Size))
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Errorf("Section %s not zeroed", sec.Name)
			}
		}
	}
}

// Test randomizing section names
func TestELFRandomizeSectionNames(t *testing.T) {
	elfFile := &elfrw.ELFFile{
		Is64Bit: true,
		Sections: []elfrw.Section{
			{Name: ".text"}, {Name: ".data"}, {Name: ".shstrtab"},
		},
	}
	// Provide minimal ELF header for parsing
	elfFile.RawData = make([]byte, 1024)
	// ELF magic
	elfFile.RawData[0] = 0x7f
	elfFile.RawData[1] = 'E'
	elfFile.RawData[2] = 'L'
	elfFile.RawData[3] = 'F'
	// Class (64-bit)
	elfFile.RawData[4] = 2
	// Data (little endian)
	elfFile.RawData[5] = 1
	// Version
	elfFile.RawData[6] = 1
	// OS ABI (none)
	elfFile.RawData[7] = 0
	// ABI Version
	elfFile.RawData[8] = 0
	// Type (ET_EXEC)
	binary.LittleEndian.PutUint16(elfFile.RawData[16:18], uint16(elf.ET_EXEC))
	// Machine (X86_64)
	binary.LittleEndian.PutUint16(elfFile.RawData[18:20], uint16(elf.EM_X86_64))
	// Version (Current)
	binary.LittleEndian.PutUint32(elfFile.RawData[20:24], uint32(elf.EV_CURRENT))

	// Entry point address (dummy)
	binary.LittleEndian.PutUint64(elfFile.RawData[24:32], 0x400000)
	// Program header offset (dummy, but non-zero)
	binary.LittleEndian.PutUint64(elfFile.RawData[32:40], 64) // e_phoff
	// Section header offset (dummy, but non-zero)
	binary.LittleEndian.PutUint64(elfFile.RawData[40:48], 128) // e_shoff
	// Flags (dummy)
	binary.LittleEndian.PutUint32(elfFile.RawData[48:52], 0)
	// ELF header size
	binary.LittleEndian.PutUint16(elfFile.RawData[52:54], elfHeaderSize)
	// Program header entry size
	binary.LittleEndian.PutUint16(elfFile.RawData[54:56], programHeaderSize)
	// Number of program headers (dummy, >0)
	binary.LittleEndian.PutUint16(elfFile.RawData[56:58], 1)
	// Section header entry size
	binary.LittleEndian.PutUint16(elfFile.RawData[58:60], sectionHeaderSize)
	// Number of section headers (dummy, >0, matches elfFile.Sections length for simplicity in mock)
	binary.LittleEndian.PutUint16(elfFile.RawData[60:62], uint16(len(elfFile.Sections)))
	// Section header string table index (dummy, needs to be < number of sections)
	binary.LittleEndian.PutUint16(elfFile.RawData[62:64], 1) // e_shstrndx, make it point to .data for this mock

	// Parse the raw data using the project's elf_reader
	parsedELF, err := elf_reader.ParseELFFile(elfFile.RawData)
	if err != nil {
		t.Fatalf("Failed to parse mock ELF data with elf_reader: %v", err)
	}
	elfFile.ELF = parsedELF

	if err := elfFile.RandomizeSectionNames(); err != nil {
		t.Fatalf("RandomizeSectionNames failed: %v", err)
	}

	nameRegex := regexp.MustCompile(`^\.[a-z]{7}$`)
	for _, sec := range elfFile.Sections {
		if sec.Name == "" { // Skip empty names which are not randomized
			continue
		}
		if !nameRegex.MatchString(sec.Name) {
			t.Errorf("Section name '%s' not randomized correctly (expected format .xxxxxxx with 7 lowercase letters)", sec.Name)
		}
	}
}

// Test obfuscating base addresses
func TestELFObfuscateBaseAddresses(t *testing.T) {
	elff := &elfrw.ELFFile{
		Is64Bit: true,
		Segments: []elfrw.Segment{
			{Offset: 0x1000, Size: 0x200, Flags: pfRead | pfExecute},
			{Offset: 0x2000, Size: 0x100, Flags: pfRead | shfWrite},
		},
	}
	elff.RawData = make([]byte, 4096)

	// Add a valid ELF header
	elff.RawData[0] = 0x7f // ELF magic number
	elff.RawData[1] = 'E'
	elff.RawData[2] = 'L'
	elff.RawData[3] = 'F'
	elff.RawData[4] = 2 // EI_CLASS: 64-bit
	elff.RawData[5] = 1 // EI_DATA: little endian
	elff.RawData[6] = 1 // EI_VERSION: current version
	elff.RawData[7] = 0 // EI_OSABI: System V
	elff.RawData[8] = 0 // EI_ABIVERSION: 0

	// e_type: ET_EXEC (executable)
	binary.LittleEndian.PutUint16(elff.RawData[16:18], 2)

	// e_machine: EM_X86_64
	binary.LittleEndian.PutUint16(elff.RawData[18:20], 62)

	// e_entry: Entry point address
	binary.LittleEndian.PutUint64(elff.RawData[24:32], 0x401000)

	// e_phoff: Program header table offset
	binary.LittleEndian.PutUint64(elff.RawData[32:40], 64)

	// e_shoff: Section header table offset
	binary.LittleEndian.PutUint64(elff.RawData[40:48], 512)

	// e_shentsize: Section header entry size
	binary.LittleEndian.PutUint16(elff.RawData[58:60], 64)

	// e_shnum: Section header count
	binary.LittleEndian.PutUint16(elff.RawData[60:62], 5)

	// e_shstrndx: Section name string table index
	binary.LittleEndian.PutUint16(elff.RawData[62:64], 1)

	if err := elff.ObfuscateBaseAddresses(); err != nil {
		t.Fatalf("ObfuscateBaseAddresses failed: %v", err)
	}

	newEntry := binary.LittleEndian.Uint64(elff.RawData[24:32])
	if newEntry%0x1000 != 0 {
		t.Errorf("New entry point %x not aligned to 0x1000", newEntry)
	}
}

// Test obfuscating exported functions
func TestELFObfuscateExportedFunctions(t *testing.T) {
	elfFile := &elfrw.ELFFile{
		Is64Bit: true,
		Sections: []elfrw.Section{
			{Name: ".dynstr", Offset: 0x100, Size: 0x50},
			{Name: ".dynsym", Offset: 0x200, Size: 0x60},
		},
	}
	elfFile.RawData = make([]byte, 1024) // Increased size

	// Minimal ELF header for parsing
	elfFile.RawData[0] = 0x7f
	elfFile.RawData[1] = 'E'
	elfFile.RawData[2] = 'L'
	elfFile.RawData[3] = 'F'
	elfFile.RawData[4] = 2                                                    // Class (64-bit)
	elfFile.RawData[5] = 1                                                    // Data (little endian)
	elfFile.RawData[6] = 1                                                    // Version
	binary.LittleEndian.PutUint16(elfFile.RawData[16:18], uint16(elf.ET_DYN)) // Type (ET_DYN for .dynsym/.dynstr)
	binary.LittleEndian.PutUint16(elfFile.RawData[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfFile.RawData[20:24], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint64(elfFile.RawData[32:40], 64)  // e_phoff (dummy)
	binary.LittleEndian.PutUint64(elfFile.RawData[40:48], 128) // e_shoff (dummy)
	binary.LittleEndian.PutUint16(elfFile.RawData[52:54], elfHeaderSize)
	binary.LittleEndian.PutUint16(elfFile.RawData[54:56], programHeaderSize)
	binary.LittleEndian.PutUint16(elfFile.RawData[56:58], 0) // No program headers for this test focus
	binary.LittleEndian.PutUint16(elfFile.RawData[58:60], sectionHeaderSize)
	binary.LittleEndian.PutUint16(elfFile.RawData[60:62], uint16(len(elfFile.Sections))) // Num sections
	// e_shstrndx: find .dynstr and set its index. For simplicity, assume it's the first if available.
	shstrndx := uint16(0)
	for i, sec := range elfFile.Sections {
		if sec.Name == ".dynstr" { // A common choice for shstrndx in dynamic ELFs can be the .dynstr itself or other strtab
			shstrndx = uint16(i) // Or a dedicated .shstrtab if present and mocked
			break
		}
	}
	binary.LittleEndian.PutUint16(elfFile.RawData[62:64], shstrndx)

	// Populate .dynstr and .dynsym data
	copy(elfFile.RawData[0x100:0x100+0x50], []byte("\x00func1\x00func2\x00"))
	// Initialize .dynsym with some dummy data, 3 symbols
	syms := make([]byte, elf64SymSize*3)
	binary.LittleEndian.PutUint32(syms[0:4], 1)                         // st_name: offset to "func1" in .dynstr
	syms[4] = elf64STInfo(uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC))   // st_info: global function
	binary.LittleEndian.PutUint32(syms[elf64SymSize:elf64SymSize+4], 7) // st_name: offset to "func2"
	syms[elf64SymSize+4] = elf64STInfo(uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC))
	copy(elfFile.RawData[0x200:0x200+len(syms)], syms)

	parsedELF, err := elf_reader.ParseELFFile(elfFile.RawData)
	if err != nil {
		t.Fatalf("Failed to parse mock ELF data: %v", err)
	}
	elfFile.ELF = parsedELF

	if err := elfFile.ObfuscateExportedFunctions(); err != nil {
		t.Fatalf("ObfuscateExportedFunctions failed: %v", err)
	}

	// Check that original names are gone from .dynstr
	dynstrSectionData := elfFile.RawData[elfFile.Sections[0].Offset : elfFile.Sections[0].Offset+elfFile.Sections[0].Size]
	if bytes.Contains(dynstrSectionData, []byte("func1")) {
		t.Errorf("Original function name 'func1' not obfuscated in .dynstr")
	}
	if bytes.Contains(dynstrSectionData, []byte("func2")) {
		t.Errorf("Original function name 'func2' not obfuscated in .dynstr")
	}

	// Further checks could verify new names exist and .dynsym entries are updated
	// For now, just ensure no error and old names are gone.
}
