package elfrw

import (
	"debug/elf"
	"fmt"
	"math"
	"strings"
)

// Utility functions for ELF file analysis and manipulation

// CalculateEntropy calculates the entropy of data bytes
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// IsHighEntropyData checks if data has high entropy (potential encryption/compression)
func IsHighEntropyData(data []byte) bool {
	entropy := CalculateEntropy(data)
	return entropy > 7.0 // High entropy threshold for binary data
}

// ExtractPrintableStrings extracts printable ASCII strings from data
func ExtractPrintableStrings(data []byte, minLen int) []string {
	if minLen < 4 {
		minLen = 4
	}

	var results []string
	var current []byte

	for _, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				results = append(results, string(current))
			}
			current = nil
		}
	}

	if len(current) >= minLen {
		results = append(results, string(current))
	}

	return results
}

// DecodeSectionFlags converts ELF section flags to human-readable string
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

// DecodeSegmentFlags converts ELF segment flags to human-readable string
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

// GetSectionTypeName returns human-readable section type name
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

// GetSegmentTypeName returns human-readable segment type name
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

// ELFFile utility methods

// GetSectionByName finds a section by name
func (e *ELFFile) GetSectionByName(name string) (*Section, error) {
	for i := range e.Sections {
		if e.Sections[i].Name == name {
			return &e.Sections[i], nil
		}
	}
	return nil, fmt.Errorf("section '%s' not found", name)
}

// GetSectionByIndex returns section by index
func (e *ELFFile) GetSectionByIndex(index int) (*Section, error) {
	if index < 0 || index >= len(e.Sections) {
		return nil, fmt.Errorf("section index out of bounds: %d", index)
	}
	return &e.Sections[index], nil
}

// GetExecutableSections returns all executable sections
func (e *ELFFile) GetExecutableSections() []Section {
	var execSections []Section
	for _, section := range e.Sections {
		if section.IsExecutable {
			execSections = append(execSections, section)
		}
	}
	return execSections
}

// GetLoadableSegments returns all loadable segments
func (e *ELFFile) GetLoadableSegments() []Segment {
	var loadableSegments []Segment
	for _, segment := range e.Segments {
		if segment.Loadable {
			loadableSegments = append(loadableSegments, segment)
		}
	}
	return loadableSegments
}

// IsExecutable checks if the ELF file is executable
func (e *ELFFile) IsExecutable() bool {
	return e.ELF != nil && e.ELF.GetFileType() == 2 // ET_EXEC
}

// IsDynamic checks if the ELF file is a dynamic library
func (e *ELFFile) IsDynamic() bool {
	return e.ELF != nil && e.ELF.GetFileType() == 3 // ET_DYN
}

// IsSharedObject checks if the ELF file is a shared object
func (e *ELFFile) IsSharedObject() bool {
	return e.IsDynamic()
}

// GetFileTypeName returns human-readable file type
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

// GetMachineName returns human-readable machine type
func (e *ELFFile) GetMachineName() string {
	if e.ELF == nil {
		return "Unknown"
	}
	return e.machineType
}

// GetEntryPoint returns the entry point address
func (e *ELFFile) GetEntryPoint() uint64 {
	return e.entryPoint
}

// GetFileType returns the ELF file type
func (e *ELFFile) GetFileType() uint16 {
	if e.ELF == nil {
		return 0
	}
	return uint16(e.ELF.GetFileType())
}

// AlignUp aligns a value up to the specified alignment
func AlignUp(value, alignment uint64) uint64 {
	if alignment == 0 {
		return value
	}
	return ((value + alignment - 1) / alignment) * alignment
}

// AlignDown aligns a value down to the specified alignment
func AlignDown(value, alignment uint64) uint64 {
	if alignment == 0 {
		return value
	}
	return (value / alignment) * alignment
}
