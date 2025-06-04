package perw

import (
	"debug/pe"
	"fmt"
	"strings"
)

func (p *PEFile) GetFileType() string {
	if p.PE == nil {
		return "Unknown"
	}
	c := p.PE.FileHeader.Characteristics
	switch {
	case c&pe.IMAGE_FILE_DLL != 0:
		return "DLL"
	case c&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0:
		return "EXE"
	default:
		return "Unknown"
	}
}

func (p *PEFile) GetSectionCount() int {
	return len(p.Sections)
}

func (p *PEFile) GetSectionByName(name string) (*Section, error) {
	for _, section := range p.Sections {
		if strings.EqualFold(strings.TrimRight(section.Name, "\x00"), name) {
			return &section, nil
		}
	}
	return nil, fmt.Errorf("section '%s' not found", name)
}

func (p *PEFile) GetSectionByIndex(index int) (*Section, error) {
	if index < 0 || index >= len(p.Sections) {
		return nil, fmt.Errorf("section index out of bounds: %d", index)
	}
	return &p.Sections[index], nil
}

func (p *PEFile) GetSectionContent(index int) ([]byte, error) {
	if index < 0 || index >= len(p.Sections) {
		return nil, fmt.Errorf("section index out of bounds: %d", index)
	}
	section := p.Sections[index]
	if section.Offset <= 0 || section.Size <= 0 {
		return []byte{}, nil
	}
	return p.ReadBytes(section.Offset, int(section.Size))
}

func (p *PEFile) IsExecutable() bool {
	return p.PE.FileHeader.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0
}

func (p *PEFile) IsDLL() bool {
	return p.PE.FileHeader.Characteristics&pe.IMAGE_FILE_DLL != 0
}

func (p *PEFile) GetEntryPoint() (uint32, error) {
	if p.PE == nil || p.PE.OptionalHeader == nil {
		return 0, fmt.Errorf("OptionalHeader not present")
	}
	switch oh := p.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.AddressOfEntryPoint, nil
	case *pe.OptionalHeader64:
		return oh.AddressOfEntryPoint, nil
	default:
		return 0, fmt.Errorf("unknown OptionalHeader type")
	}
}

func (p *PEFile) GetImageBase() (uint64, error) {
	if p.PE == nil || p.PE.OptionalHeader == nil {
		return 0, fmt.Errorf("OptionalHeader not present")
	}
	switch oh := p.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase), nil
	case *pe.OptionalHeader64:
		return oh.ImageBase, nil
	default:
		return 0, fmt.Errorf("unknown OptionalHeader type")
	}
}

func (p *PEFile) GetSectionFlags(index int) (uint32, error) {
	if index < 0 || index >= len(p.Sections) {
		return 0, fmt.Errorf("section index out of bounds: %d", index)
	}
	return p.Sections[index].Flags, nil
}

func (p *PEFile) IsSectionExecutable(index int) (bool, error) {
	return p.checkSectionFlag(index, 0x20000000) // IMAGE_SCN_MEM_EXECUTE
}

func (p *PEFile) IsSectionWritable(index int) (bool, error) {
	return p.checkSectionFlag(index, 0x80000000) // IMAGE_SCN_MEM_WRITE
}

func (p *PEFile) IsSectionReadable(index int) (bool, error) {
	return p.checkSectionFlag(index, 0x40000000) // IMAGE_SCN_MEM_READ
}

func (p *PEFile) IsSectionContainsCode(index int) (bool, error) {
	return p.checkSectionFlag(index, 0x00000020) // IMAGE_SCN_CNT_CODE
}

func (p *PEFile) IsSectionContainsInitializedData(index int) (bool, error) {
	return p.checkSectionFlag(index, 0x00000040) // IMAGE_SCN_CNT_INITIALIZED_DATA
}

func (p *PEFile) IsSectionContainsUninitializedData(index int) (bool, error) {
	return p.checkSectionFlag(index, 0x00000080) // IMAGE_SCN_CNT_UNINITIALIZED_DATA
}

func (p *PEFile) checkSectionFlag(index int, flag uint32) (bool, error) {
	flags, err := p.GetSectionFlags(index)
	if err != nil {
		return false, err
	}
	return flags&flag != 0, nil
}

// GetExecutableSections returns all executable sections
func (p *PEFile) GetExecutableSections() []Section {
	var execSections []Section
	for _, section := range p.Sections {
		if (section.Flags & pe.IMAGE_SCN_CNT_CODE) != 0 {
			execSections = append(execSections, section)
		}
	}
	return execSections
}

// IsExecutableOrShared checks if file is executable or DLL
func (p *PEFile) IsExecutableOrShared() bool {
	if p.PE == nil {
		return false
	}
	c := p.PE.FileHeader.Characteristics
	return (c&pe.IMAGE_FILE_EXECUTABLE_IMAGE) != 0 || (c&pe.IMAGE_FILE_DLL) != 0
}

// --- Section Type Utilities ---

// GetSectionTypeDescription returns a human-readable description of a section type
func GetSectionTypeDescription(sectionType SectionType) string {
	if matcher, exists := sectionMatchers[sectionType]; exists {
		return matcher.Description
	}
	return "unknown section type"
}

// IsSectionTypeRisky returns whether stripping a section type might break functionality
func IsSectionTypeRisky(sectionType SectionType) bool {
	if matcher, exists := sectionMatchers[sectionType]; exists {
		return matcher.IsRisky
	}
	return true // Assume risky if unknown
}

// shouldStripForFileType determines if a section type should be stripped for the current file type
func (p *PEFile) shouldStripForFileType(sectionType SectionType) bool {
	matcher := sectionMatchers[sectionType]
	if p.IsDLL() {
		return matcher.StripForDLL
	}
	return matcher.StripForEXE
}
