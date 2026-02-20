package perw

import (
	"encoding/binary"
	"testing"

	"gosstrip/common"
)

func TestPEInsert_updateOptionalHeaderForNewSection_UpdatesSizeOfImage(t *testing.T) {
	p := &PEFile{}
	p.RawData = make([]byte, 0x400)

	// Minimal PE layout for updateOptionalHeaderForNewSection:
	// - DOS header with e_lfanew
	// - COFF header with OptionalHeaderSize
	// - Optional header with magic, SectionAlignment, and SizeOfImage fields
	peHeaderOffset := uint32(0x80)
	binary.LittleEndian.PutUint32(p.RawData[PE_ELFANEW_OFFSET:PE_ELFANEW_OFFSET+4], peHeaderOffset)

	coffHeaderOffset := int64(peHeaderOffset) + 4
	optionalHeaderOffset := coffHeaderOffset + PE_FILE_HEADER_SIZE

	// Non-zero optional header size.
	binary.LittleEndian.PutUint16(p.RawData[coffHeaderOffset+PE_OPTSIZE_OFFSET:coffHeaderOffset+PE_OPTSIZE_OFFSET+2], 0xF0)

	// PE32+ optional header.
	binary.LittleEndian.PutUint16(p.RawData[optionalHeaderOffset:optionalHeaderOffset+2], PE64_MAGIC)

	sectionAlignment := uint32(0x1000)
	binary.LittleEndian.PutUint32(p.RawData[optionalHeaderOffset+PE64_SECTION_ALIGN:optionalHeaderOffset+PE64_SECTION_ALIGN+4], sectionAlignment)

	sizeOfImageOffset := optionalHeaderOffset + PE64_SIZE_OF_IMAGE
	binary.LittleEndian.PutUint32(p.RawData[sizeOfImageOffset:sizeOfImageOffset+4], 0x2000)

	newSection := &Section{VirtualAddress: 0x3000, VirtualSize: 0x123}
	if err := p.updateOptionalHeaderForNewSection(newSection); err != nil {
		t.Fatalf("updateOptionalHeaderForNewSection failed: %v", err)
	}

	want := common.AlignUp(newSection.VirtualAddress+newSection.VirtualSize, sectionAlignment)
	gotRaw := binary.LittleEndian.Uint32(p.RawData[sizeOfImageOffset : sizeOfImageOffset+4])
	if gotRaw != want {
		t.Fatalf("SizeOfImage not updated: got 0x%X want 0x%X", gotRaw, want)
	}
	if p.sizeOfImage != want {
		t.Fatalf("PEFile.sizeOfImage not updated: got 0x%X want 0x%X", p.sizeOfImage, want)
	}
}
