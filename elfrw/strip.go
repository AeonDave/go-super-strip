package elfrw

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"regexp"
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
	// Remove section header table
	if err := e.StripSectionTable(); err != nil {
		return err
	}
	// Remove dynamic linking sections
	if err := e.StripDynamicLinking(); err != nil {
		return err
	}
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

// StripByteRegex overwrites byte patterns matching a regex with null bytes in all sections.
func (e *ELFFile) StripByteRegex(pattern *regexp.Regexp) int {
	matchesTotal := 0
	for _, section := range e.Sections {
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}
		data, err := e.ReadBytes(section.Offset, int(section.Size))
		if err != nil {
			continue
		}
		indices := pattern.FindAllIndex(data, -1)
		if len(indices) == 0 {
			continue
		}
		for _, idx := range indices {
			for i := idx[0]; i < idx[1]; i++ {
				data[i] = 0
			}
			matchesTotal++
		}
		start := int(section.Offset)
		end := int(section.Offset + section.Size)
		if start >= 0 && end <= len(e.RawData) && end > start && len(data) == int(section.Size) {
			copy(e.RawData[start:end], data)
		}
	}
	return matchesTotal
}
