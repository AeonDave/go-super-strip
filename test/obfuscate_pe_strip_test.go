package main

import (
	"bytes"
	"gosstrip/perw"
	"regexp"
	"testing"
)

func TestPEStripAllMetadata(t *testing.T) {
	pe := &perw.PEFile{
		RawData:  make([]byte, 4096),
		Sections: []perw.Section{{Name: ".debug", Offset: 100, Size: 10}, {Name: ".strtab", Offset: 200, Size: 10}},
	}
	copy(pe.RawData[100:110], []byte("debugdata"))
	copy(pe.RawData[200:210], []byte("strtabdat"))
	err := pe.StripAllMetadata()
	if err != nil {
		t.Fatalf("StripAllMetadata failed: %v", err)
	}
	for _, sec := range pe.Sections {
		if sec.Size != 0 && sec.Offset != 0 {
			data, _ := pe.ReadBytes(sec.Offset, int(sec.Size))
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Errorf("Section %s not zeroed", sec.Name)
			}
		}
	}
}

func TestPEObfuscateAll(t *testing.T) {
	pe := &perw.PEFile{
		RawData:  make([]byte, 4096),
		Sections: []perw.Section{{Name: ".rsrc", Offset: 100, Size: 16}},
	}
	copy(pe.RawData[100:116], []byte("1234567890abcdef"))
	err := pe.ObfuscateAll()
	if err != nil {
		t.Fatalf("ObfuscateAll failed: %v", err)
	}
	zero := make([]byte, 16)
	if bytes.Equal(pe.RawData[100:116], zero) {
		t.Error("ObfuscateAll did not randomize section data")
	}
}

func TestPEStripByteRegex(t *testing.T) {
	pe := &perw.PEFile{
		RawData:  make([]byte, 256),
		Sections: []perw.Section{{Name: ".data", Offset: 0, Size: 256}},
	}
	copy(pe.RawData[0:20], []byte("UPX! signature here"))
	pat := regexp.MustCompile(`UPX!`)
	matches := pe.StripByteRegex(pat)
	if matches == 0 {
		t.Error("StripByteRegex did not find pattern")
	}
	if bytes.Contains(pe.RawData[:20], []byte("UPX!")) {
		t.Error("StripByteRegex did not remove pattern")
	}
}
