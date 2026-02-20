package elfrw

import "testing"

func TestELFCompact_serializeHeaders_PreservesEntSize_ELF64(t *testing.T) {
	e := &ELFFile{Is64Bit: true}
	// RawData[5] is EI_DATA (1 = little endian). serializeHeaders relies on getEndian().
	e.RawData = make([]byte, 16)
	e.RawData[5] = 0x01

	e.Sections = []Section{
		{Name: "", Type: SHT_NULL},
		{
			Name:      ".dynsym",
			Type:      SHT_DYNSYM,
			Flags:     0,
			Address:   0,
			Offset:    0x100,
			Size:      0x200,
			Link:      0,
			Info:      0,
			Alignment: 8,
			EntSize:   24, // Elf64_Sym
		},
	}

	data := e.serializeHeaders(map[int]uint32{0: 0, 1: 1}, -1)
	if got, want := int64(len(data)), int64(len(e.Sections))*ELF64_SHDR_SIZE; got != want {
		t.Fatalf("unexpected header table size: got %d want %d", got, want)
	}

	// Section #1 header starts at 1*ELF64_SHDR_SIZE.
	start := int64(1) * ELF64_SHDR_SIZE
	entsizeOff := start + 56 // sh_entsize offset in Elf64_Shdr
	if entsizeOff+8 > int64(len(data)) {
		t.Fatalf("entsize offset out of bounds")
	}

	got := e.getEndian().Uint64(data[entsizeOff : entsizeOff+8])
	if want := uint64(24); got != want {
		t.Fatalf("sh_entsize not preserved: got %d want %d", got, want)
	}
}
