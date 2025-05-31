package main

import (
	"encoding/binary"
	"regexp"
	"strings"
	"testing"

	"gosstrip/perw"
)

// Constants for PE structures
const (
	dosHeaderSize        = 64
	peSignatureSize      = 4
	coffFileHeaderSize   = 20
	optionalHeader64Size = 240
	sectionPeHeaderSize  = 40

	imageFileMachineAMD64 = 0x8664
	pe32PlusMagic         = 0x20b

	debugDirectoryOffset      = 128
	tlsDirectoryOffset        = 144
	loadConfigDirectoryOffset = 152
)

func trimNulls(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

func createMinimalPE64(t *testing.T, imageBase uint64) *perw.PEFile {
	peFile := &perw.PEFile{Is64Bit: true}
	rawData := make([]byte, dosHeaderSize+peSignatureSize+coffFileHeaderSize+optionalHeader64Size+sectionPeHeaderSize)

	// DOS Header
	rawData[0], rawData[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(rawData[0x3C:], dosHeaderSize)

	// PE Signature
	copy(rawData[dosHeaderSize:], []byte{'P', 'E', 0, 0})

	// COFF Header
	binary.LittleEndian.PutUint16(rawData[dosHeaderSize+4:], imageFileMachineAMD64)
	binary.LittleEndian.PutUint16(rawData[dosHeaderSize+6:], 1) // Number of sections
	binary.LittleEndian.PutUint16(rawData[dosHeaderSize+16:], optionalHeader64Size)

	// Optional Header
	offset := dosHeaderSize + peSignatureSize + coffFileHeaderSize
	binary.LittleEndian.PutUint16(rawData[offset:], pe32PlusMagic)
	binary.LittleEndian.PutUint64(rawData[offset+24:], imageBase)
	binary.LittleEndian.PutUint32(rawData[offset+56:], 0x2000) // Size of image
	binary.LittleEndian.PutUint32(rawData[offset+60:], 0x200)  // Size of headers

	// Section Header
	sectionOffset := offset + optionalHeader64Size
	copy(rawData[sectionOffset:], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(rawData[sectionOffset+36:], 0x60000020)

	peFile.RawData = rawData
	peFile.Sections = []perw.Section{{Name: ".text", Flags: 0x60000020}}
	return peFile
}

func TestPERandomizeSectionNames(t *testing.T) {
	peFile := createMinimalPE64(t, 0x140000000)
	originalName := peFile.Sections[0].Name

	if err := peFile.RandomizeSectionNames(); err != nil {
		t.Fatalf("RandomizeSectionNames failed: %v", err)
	}

	newName := peFile.Sections[0].Name
	// PE section names are 8 bytes, e.g., ".text\0\0\0". Randomization aims for ".xxxxxxx\0".
	// The .Name field in perw.Section is trimmed of nulls.
	expectedPattern := regexp.MustCompile(`^\.[a-z]{7}$`)
	if originalName == newName || !expectedPattern.MatchString(newName) {
		t.Errorf("Section name '%s' (original: '%s') not randomized correctly. Expected format like .xxxxxxx", newName, originalName)
	}
}

func TestPEObfuscateBaseAddresses(t *testing.T) {
	peFile := createMinimalPE64(t, 0x140000000)
	// Correct offset for ImageBase in PE32+ Optional Header is OptionalHeaderStart + 24 bytes.
	// OptionalHeaderStart = dosHeaderSize(64) + peSignatureSize(4) + coffFileHeaderSize(20) = 88.
	// ImageBaseOffset = 88 + 24 = 112.
	imageBaseOffset := int64(dosHeaderSize + peSignatureSize + coffFileHeaderSize + 24)
	initialBase := binary.LittleEndian.Uint64(peFile.RawData[imageBaseOffset : imageBaseOffset+8])

	if err := peFile.ObfuscateBaseAddresses(); err != nil {
		t.Fatalf("ObfuscateBaseAddresses failed: %v", err)
	}

	newBase := binary.LittleEndian.Uint64(peFile.RawData[imageBaseOffset : imageBaseOffset+8])
	if newBase == initialBase || newBase%0x10000 != 0 {
		t.Errorf("Base address not obfuscated correctly: %X", newBase)
	}
}

func TestPEObfuscateDirectory(t *testing.T) {
	tests := []struct {
		name     string
		offset   int64
		function func(*perw.PEFile) error
	}{
		{"Debug Directory", debugDirectoryOffset, (*perw.PEFile).ObfuscateDebugDirectory},
		{"TLS Directory", tlsDirectoryOffset, (*perw.PEFile).ObfuscateTLSDirectory},
		{"Load Config Directory", loadConfigDirectoryOffset, (*perw.PEFile).ObfuscateLoadConfig},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peFile := createMinimalPE64(t, 0x140000000)
			// Calculate the actual offset of the directory entry in RawData
			// OptionalHeader starts after DOS Header (64), PE Sig (4), COFF Header (20)
			optionalHeaderStartOffset := int64(dosHeaderSize + peSignatureSize + coffFileHeaderSize) // 88
			// tt.offset is the offset of the specific DataDirectory entry from the start of OptionalHeader
			dirEntryInRawDataOffset := optionalHeaderStartOffset + tt.offset

			binary.LittleEndian.PutUint32(peFile.RawData[dirEntryInRawDataOffset:], 0x1000)  // VA
			binary.LittleEndian.PutUint32(peFile.RawData[dirEntryInRawDataOffset+4:], 0x100) // Size

			if err := tt.function(peFile); err != nil {
				t.Fatalf("%s failed: %v", tt.name, err)
			}

			va := binary.LittleEndian.Uint32(peFile.RawData[dirEntryInRawDataOffset:])
			size := binary.LittleEndian.Uint32(peFile.RawData[dirEntryInRawDataOffset+4:])
			if va != 0 || size != 0 {
				t.Errorf("%s not zeroed. VA: %X, Size: %X", tt.name, va, size)
			}
		})
	}
}
