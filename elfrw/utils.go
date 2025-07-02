package elfrw

import (
	"debug/elf"
	"fmt"
	"strings"
)

func ContainsSuspiciousPattern(s string) bool {
	suspiciousPatterns := []string{
		"\\x", "0x", "%x", "\\u", "\\U",
		"[\\", "\\]", "^_", "A\\A", "\\$",
	}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	return false
}

func DecodeSectionFlags(flags uint64) string {
	var flagStrs []string

	if flags&uint64(elf.SHF_WRITE) != 0 {
		flagStrs = append(flagStrs, "WRITE")
	}
	if flags&uint64(elf.SHF_ALLOC) != 0 {
		flagStrs = append(flagStrs, "ALLOC")
	}
	if flags&uint64(elf.SHF_EXECINSTR) != 0 {
		flagStrs = append(flagStrs, "EXEC")
	}
	if flags&uint64(elf.SHF_MERGE) != 0 {
		flagStrs = append(flagStrs, "MERGE")
	}
	if flags&uint64(elf.SHF_STRINGS) != 0 {
		flagStrs = append(flagStrs, "STRINGS")
	}
	if flags&uint64(elf.SHF_INFO_LINK) != 0 {
		flagStrs = append(flagStrs, "INFO_LINK")
	}
	if flags&uint64(elf.SHF_LINK_ORDER) != 0 {
		flagStrs = append(flagStrs, "LINK_ORDER")
	}
	if flags&uint64(elf.SHF_OS_NONCONFORMING) != 0 {
		flagStrs = append(flagStrs, "OS_NONCONFORMING")
	}
	if flags&uint64(elf.SHF_GROUP) != 0 {
		flagStrs = append(flagStrs, "GROUP")
	}
	if flags&uint64(elf.SHF_TLS) != 0 {
		flagStrs = append(flagStrs, "TLS")
	}

	if len(flagStrs) == 0 {
		return "None"
	}

	return strings.Join(flagStrs, ", ")
}

func DecodeSegmentFlags(flags uint32) string {
	var flagStrs []string

	if flags&uint32(elf.PF_R) != 0 {
		flagStrs = append(flagStrs, "READ")
	}
	if flags&uint32(elf.PF_W) != 0 {
		flagStrs = append(flagStrs, "WRITE")
	}
	if flags&uint32(elf.PF_X) != 0 {
		flagStrs = append(flagStrs, "EXEC")
	}

	if len(flagStrs) == 0 {
		return "None"
	}

	return strings.Join(flagStrs, ", ")
}

func GetSectionTypeName(sectionType uint32) string {
	switch elf.SectionType(sectionType) {
	case elf.SHT_NULL:
		return "NULL"
	case elf.SHT_PROGBITS:
		return "PROGBITS"
	case elf.SHT_SYMTAB:
		return "SYMTAB"
	case elf.SHT_STRTAB:
		return "STRTAB"
	case elf.SHT_RELA:
		return "RELA"
	case elf.SHT_HASH:
		return "HASH"
	case elf.SHT_DYNAMIC:
		return "DYNAMIC"
	case elf.SHT_NOTE:
		return "NOTE"
	case elf.SHT_NOBITS:
		return "NOBITS"
	case elf.SHT_REL:
		return "REL"
	case elf.SHT_SHLIB:
		return "SHLIB"
	case elf.SHT_DYNSYM:
		return "DYNSYM"
	case elf.SHT_INIT_ARRAY:
		return "INIT_ARRAY"
	case elf.SHT_FINI_ARRAY:
		return "FINI_ARRAY"
	case elf.SHT_PREINIT_ARRAY:
		return "PREINIT_ARRAY"
	case elf.SHT_GROUP:
		return "GROUP"
	case elf.SHT_SYMTAB_SHNDX:
		return "SYMTAB_SHNDX"
	default:
		if sectionType >= uint32(elf.SHT_LOPROC) && sectionType <= uint32(elf.SHT_HIPROC) {
			return "PROCESSOR_SPECIFIC"
		}
		if sectionType >= uint32(elf.SHT_LOUSER) && sectionType <= uint32(elf.SHT_HIUSER) {
			return "USER_DEFINED"
		}
		return fmt.Sprintf("UNKNOWN(0x%x)", sectionType)
	}
}

func GetSegmentTypeName(segmentType uint32) string {
	switch elf.ProgType(segmentType) {
	case elf.PT_NULL:
		return "NULL"
	case elf.PT_LOAD:
		return "LOAD"
	case elf.PT_DYNAMIC:
		return "DYNAMIC"
	case elf.PT_INTERP:
		return "INTERP"
	case elf.PT_NOTE:
		return "NOTE"
	case elf.PT_SHLIB:
		return "SHLIB"
	case elf.PT_PHDR:
		return "PHDR"
	case elf.PT_TLS:
		return "TLS"
	default:
		if segmentType >= uint32(elf.PT_LOPROC) && segmentType <= uint32(elf.PT_HIPROC) {
			return "PROCESSOR_SPECIFIC"
		}
		return fmt.Sprintf("UNKNOWN(0x%x)", segmentType)
	}
}

func (e *ELFFile) GetSectionByName(name string) (*Section, error) {
	for i := range e.Sections {
		if e.Sections[i].Name == name {
			return &e.Sections[i], nil
		}
	}
	return nil, fmt.Errorf("section '%s' not found", name)
}

func (e *ELFFile) GetSectionByIndex(index int) (*Section, error) {
	if index < 0 || index >= len(e.Sections) {
		return nil, fmt.Errorf("section index out of bounds: %d", index)
	}
	return &e.Sections[index], nil
}

func (e *ELFFile) GetExecutableSections() []Section {
	var execSections []Section
	for _, section := range e.Sections {
		if section.IsExecutable {
			execSections = append(execSections, section)
		}
	}
	return execSections
}

func (e *ELFFile) GetLoadableSegments() []Segment {
	var loadableSegments []Segment
	for _, segment := range e.Segments {
		if segment.Loadable {
			loadableSegments = append(loadableSegments, segment)
		}
	}
	return loadableSegments
}

func (e *ELFFile) IsExecutable() bool {
	return e.ELF != nil && e.ELF.GetFileType() == 2 // ET_EXEC
}

func (e *ELFFile) IsDynamic() bool {
	return e.ELF != nil && e.ELF.GetFileType() == 3 // ET_DYN
}

func (e *ELFFile) IsSharedObject() bool {
	return e.IsDynamic()
}

func (e *ELFFile) GetFileTypeName() string {
	if e.ELF == nil {
		return "Unknown"
	}

	switch e.ELF.GetFileType() {
	case 0:
		return "No file type"
	case 1:
		return "Relocatable"
	case 2:
		return "Executable"
	case 3:
		return "Shared object"
	case 4:
		return "Core file"
	default:
		return fmt.Sprintf("Unknown(0x%x)", e.ELF.GetFileType())
	}
}

func (e *ELFFile) GetMachineName() string {
	if e.ELF == nil {
		return "Unknown"
	}
	return e.machineType
}

func (e *ELFFile) GetEntryPoint() uint64 {
	return e.entryPoint
}

func (e *ELFFile) GetFileType() uint16 {
	if e.ELF == nil {
		return 0
	}
	return uint16(e.ELF.GetFileType())
}

func AlignUp(value, alignment uint64) uint64 {
	if alignment == 0 {
		return value
	}
	return ((value + alignment - 1) / alignment) * alignment
}

func AlignDown(value, alignment uint64) uint64 {
	if alignment == 0 {
		return value
	}
	return (value / alignment) * alignment
}
