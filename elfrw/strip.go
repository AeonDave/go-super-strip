package elfrw

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
)

func (e *ELFFile) IsLittleEndian() bool {
	return e.RawData[5] == 1 // ELFDATA2LSB
}

func (e *ELFFile) GetEndian() binary.ByteOrder {
	if e.IsLittleEndian() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func (e *ELFFile) ReadBytes(offset uint64, size int) ([]byte, error) {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return nil, fmt.Errorf("read beyond file limits: offset %d, size %d", offset, size)
	}
	result := make([]byte, size)
	copy(result, e.RawData[offset:offset+uint64(size)])
	return result, nil
}

func (e *ELFFile) ZeroFill(offset uint64, size int) error {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return fmt.Errorf("write beyond file limits: offset %d, size %d")
	}
	for i := uint64(0); i < uint64(size); i++ {
		e.RawData[offset+i] = 0
	}
	return nil
}

func (e *ELFFile) StripSectionTable() error {
	endianness := e.GetEndian()
	var shoffPos, shNumPos, shStrNdxPos int
	if e.Is64Bit {
		shoffPos = 40
		shNumPos = 60
		shStrNdxPos = 62
	} else {
		shoffPos = 32
		shNumPos = 48
		shStrNdxPos = 50
	}
	if e.Is64Bit {
		var zero uint64 = 0
		err := WriteAtOffset(e.RawData, uint64(shoffPos), endianness, zero)
		if err != nil {
			return err
		}
	} else {
		var zero uint32 = 0
		err := WriteAtOffset(e.RawData, uint64(shoffPos), endianness, zero)
		if err != nil {
			return err
		}
	}
	var zeroShort uint16 = 0
	err := WriteAtOffset(e.RawData, uint64(shNumPos), endianness, zeroShort)
	if err != nil {
		return err
	}
	err = WriteAtOffset(e.RawData, uint64(shStrNdxPos), endianness, zeroShort)
	if err != nil {
		return err
	}
	return nil
}

func (e *ELFFile) StripNonLoadable() error {
	for i, segment := range e.Segments {
		if !segment.Loadable {
			if segment.Offset > 0 && segment.Size > 0 {
				err := e.ZeroFill(segment.Offset, int(segment.Size))
				if err != nil {
					return err
				}
			}
			segment.Offset = 0
			segment.Size = 0
			e.Segments[i] = segment
		}
	}
	return e.UpdateProgramHeaders()
}

func (e *ELFFile) RandomizeSectionNames() error {
	var shStrNdxPos int
	if e.Is64Bit {
		shStrNdxPos = 62
	} else {
		shStrNdxPos = 50
	}

	endianness := e.GetEndian()
	var shstrtabIndex uint16

	if endianness == binary.LittleEndian {
		shstrtabIndex = binary.LittleEndian.Uint16(e.RawData[shStrNdxPos : shStrNdxPos+2])
	} else {
		shstrtabIndex = binary.BigEndian.Uint16(e.RawData[shStrNdxPos : shStrNdxPos+2])
	}
	shstrtabContent, err := e.ELF.GetSectionContent(shstrtabIndex)
	if err != nil {
		return fmt.Errorf("impossibile leggere la tabella delle stringhe: %w", err)
	}
	shstrtabHeader, err := e.ELF.GetSectionHeader(shstrtabIndex)
	if err != nil {
		return fmt.Errorf("impossibile leggere l'header della tabella delle stringhe: %w", err)
	}
	newShstrtab := make([]byte, 0, len(shstrtabContent))
	newShstrtab = append(newShstrtab, 0)
	nameOffsets := make(map[string]uint32)
	for i := range e.Sections {
		if e.Sections[i].Name == "" {
			continue
		}
		randomName := fmt.Sprintf(".s%d", rand.Intn(10000))
		nameOffsets[e.Sections[i].Name] = uint32(len(newShstrtab))
		newShstrtab = append(newShstrtab, []byte(randomName)...)
		newShstrtab = append(newShstrtab, 0)
		e.Sections[i].Name = randomName
	}
	shstrtabOffset := shstrtabHeader.GetFileOffset()
	copy(e.RawData[shstrtabOffset:shstrtabOffset+uint64(len(newShstrtab))], newShstrtab)
	if len(newShstrtab) < len(shstrtabContent) {
		for i := len(newShstrtab); i < len(shstrtabContent); i++ {
			e.RawData[shstrtabOffset+uint64(i)] = 0
		}
	}
	var shoffPos int
	if e.Is64Bit {
		shoffPos = 40
	} else {
		shoffPos = 32
	}
	var sectionHeaderOffset uint64
	if e.Is64Bit {
		if endianness == binary.LittleEndian {
			sectionHeaderOffset = binary.LittleEndian.Uint64(e.RawData[shoffPos : shoffPos+8])
		} else {
			sectionHeaderOffset = binary.BigEndian.Uint64(e.RawData[shoffPos : shoffPos+8])
		}
	} else {
		if endianness == binary.LittleEndian {
			sectionHeaderOffset = uint64(binary.LittleEndian.Uint32(e.RawData[shoffPos : shoffPos+4]))
		} else {
			sectionHeaderOffset = uint64(binary.BigEndian.Uint32(e.RawData[shoffPos : shoffPos+4]))
		}
	}
	var shentsizePos int
	if e.Is64Bit {
		shentsizePos = 58
	} else {
		shentsizePos = 46
	}
	var sectionHeaderEntrySize uint16
	if endianness == binary.LittleEndian {
		sectionHeaderEntrySize = binary.LittleEndian.Uint16(e.RawData[shentsizePos : shentsizePos+2])
	} else {
		sectionHeaderEntrySize = binary.BigEndian.Uint16(e.RawData[shentsizePos : shentsizePos+2])
	}
	for i := uint16(0); i < e.ELF.GetSectionCount(); i++ {
		oldName, err := e.ELF.GetSectionName(i)
		if err != nil {
			continue
		}
		nameOffset := sectionHeaderOffset + uint64(i)*uint64(sectionHeaderEntrySize)
		if newOffset, ok := nameOffsets[oldName]; ok {
			err := WriteAtOffset(e.RawData, nameOffset, endianness, newOffset)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *ELFFile) StripSectionsByNames(names []string, prefix bool) error {
	for i, section := range e.Sections {
		for _, name := range names {
			if (prefix && strings.HasPrefix(section.Name, name)) || (!prefix && section.Name == name) {
				if section.Offset > 0 && section.Size > 0 {
					err := e.ZeroFill(section.Offset, int(section.Size))
					if err != nil {
						return err
					}
				}
				section.Offset = 0
				section.Size = 0
				e.Sections[i] = section
			}
		}
	}
	return e.UpdateSectionHeaders()
}

func (e *ELFFile) ModifyELFHeader() error {
	endianness := e.GetEndian()
	var timestampOffset int
	if e.Is64Bit {
		timestampOffset = 16
		for i := 0; i < 8; i++ {
			e.RawData[timestampOffset+i] = byte(rand.Intn(256))
		}
	} else {
		timestampOffset = 16
		for i := 0; i < 4; i++ {
			e.RawData[timestampOffset+i] = byte(rand.Intn(256))
		}
	}

	var flagsOffset int
	if e.Is64Bit {
		flagsOffset = 48
		err := WriteAtOffset(e.RawData, uint64(flagsOffset), endianness, uint32(rand.Intn(0x10)))
		if err != nil {
			return err
		}
	} else {
		flagsOffset = 36
		err := WriteAtOffset(e.RawData, uint64(flagsOffset), endianness, uint32(rand.Intn(0x10)))
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *ELFFile) StripDynamicLinking() error {
	return e.StripSectionsByNames([]string{".dynamic", ".dynstr", ".dynsym"}, false)
}

var (
	SymbolsSectionsExact = []string{
		".symtab",
		".dynsym",
	}
	StringSectionsExact = []string{
		".strtab",
	}
	DebugSectionsExact = []string{
		".debug",
		".stab",
		".stabstr",
		".gdb_index",
		".line",
		".zdebug_",
	}
	DebugSectionsPrefix = []string{
		".debug_",
		".zdebug_",
	}
	BuildInfoSectionsExact = []string{
		".gnu.build.attributes",
		".gnu.version",
		".gnu.version_r",
		".gnu.version_d",
		".gnu.warning",
		".note.gnu.build-id",
		".note.ABI-tag",
		".note.gnu.property",
		".comment",
		".buildid",
		".SUNW_",
		".gnu.liblist",
		".gnu.conflict",
		".gnu.prelink_undo",
	}
	BuildInfoSectionsPrefix = []string{
		".note",
	}
	ProfilingSectionsExact = []string{
		".gmon",
		".profile",
	}
	ExceptionSectionsExact = []string{
		".eh_frame",
		".eh_frame_hdr",
		".gcc_except_table",
		".pdr",
		".mdebug",
	}
	ArchSectionsPrefix = []string{
		".ARM.",
		".MIPS.",
		".xtensa.",
	}
	PLTRelocSectionsExact = []string{
		".plt.got",
		".plt.sec",
	}
	PLTRelocSectionsPrefix = []string{
		".rel",
		".rela",
	}
)

func (e *ELFFile) StripAllMetadata() error {
	// Symbols
	if err := e.StripSectionsByNames(SymbolsSectionsExact, false); err != nil {
		return err
	}
	// Strings
	if err := e.StripSectionsByNames(StringSectionsExact, false); err != nil {
		return err
	}
	// Debug
	if err := e.StripSectionsByNames(DebugSectionsExact, false); err != nil {
		return err
	}
	if err := e.StripSectionsByNames(DebugSectionsPrefix, true); err != nil {
		return err
	}
	// Build info/toolchain
	if err := e.StripSectionsByNames(BuildInfoSectionsExact, false); err != nil {
		return err
	}
	if err := e.StripSectionsByNames(BuildInfoSectionsPrefix, true); err != nil {
		return err
	}
	// Profiling
	if err := e.StripSectionsByNames(ProfilingSectionsExact, false); err != nil {
		return err
	}
	// Exception/stack unwinding
	if err := e.StripSectionsByNames(ExceptionSectionsExact, false); err != nil {
		return err
	}
	// Arch
	if err := e.StripSectionsByNames(ArchSectionsPrefix, true); err != nil {
		return err
	}
	// PLT/relocation
	if err := e.StripSectionsByNames(PLTRelocSectionsExact, false); err != nil {
		return err
	}
	if err := e.StripSectionsByNames(PLTRelocSectionsPrefix, true); err != nil {
		return err
	}
	return nil
}
