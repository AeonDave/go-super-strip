package main

import (
	"bytes"
	"gosstrip/elfrw"
	"regexp"
	"testing"
)

func TestELFStripAllMetadata(t *testing.T) {
	// Dummy ELFFile with fake sections for test
	elf := &elfrw.ELFFile{
		RawData:  make([]byte, 4096),
		Is64Bit:  true,
		Sections: []elfrw.Section{{Name: ".debug", Offset: 100, Size: 10}, {Name: ".strtab", Offset: 200, Size: 10}},
	}
	copy(elf.RawData[100:110], []byte("debugdata"))
	copy(elf.RawData[200:210], []byte("strtabdat"))
	err := elf.StripAllMetadata()
	if err != nil {
		t.Fatalf("StripAllMetadata failed: %v", err)
	}
	for _, sec := range elf.Sections {
		if sec.Size != 0 && sec.Offset != 0 {
			data, _ := elf.ReadBytes(sec.Offset, int(sec.Size))
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Errorf("Section %s not zeroed", sec.Name)
			}
		}
	}
}

func TestELFObfuscateAll(t *testing.T) {
	elf := &elfrw.ELFFile{
		RawData:  make([]byte, 4096),
		Is64Bit:  true,
		Sections: []elfrw.Section{{Name: ".note", Offset: 100, Size: 16}},
	}
	copy(elf.RawData[100:116], []byte("1234567890abcdef"))
	err := elf.ObfuscateAll()
	if err != nil {
		t.Fatalf("ObfuscateAll failed: %v", err)
	}
	// Check that section padding and reserved fields are not all zero
	zero := make([]byte, 16)
	if bytes.Equal(elf.RawData[100:116], zero) {
		t.Error("ObfuscateAll did not randomize section data")
	}
}

func TestELFStripByteRegex(t *testing.T) {
	elf := &elfrw.ELFFile{
		RawData:  make([]byte, 256),
		Is64Bit:  true,
		Sections: []elfrw.Section{{Name: ".data", Offset: 0, Size: 256}},
	}
	copy(elf.RawData[0:20], []byte("UPX! signature here"))
	pat := regexp.MustCompile(`UPX!`)
	matches := elf.StripByteRegex(pat)
	if matches == 0 {
		t.Error("StripByteRegex did not find pattern")
	}
	if bytes.Contains(elf.RawData[:20], []byte("UPX!")) {
		t.Error("StripByteRegex did not remove pattern")
	}
}
