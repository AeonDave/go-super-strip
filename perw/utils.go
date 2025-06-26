package perw

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

func IsHighEntropyString(s string) bool {
	if len(s) < 10 {
		return false
	}
	charCount := make(map[rune]int)
	for _, r := range s {
		charCount[r]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range charCount {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy > 4.5 // High entropy threshold
}

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

func ExtractSuspiciousStrings(data []byte, unicode bool) []string {
	var results []string
	var minLen = 8
	var current []byte
	for i := 0; i < len(data); i++ {
		b := data[i]
		if unicode {
			if i+1 < len(data) && data[i+1] == 0 {
				current = append(current, b)
				i++
			} else {
				if len(current) >= minLen {
					results = append(results, string(current))
				}
				current = nil
			}
		} else {
			if b >= 32 && b <= 126 {
				current = append(current, b)
			} else {
				if len(current) >= minLen {
					results = append(results, string(current))
				}
				current = nil
			}
		}
	}
	if len(current) >= minLen {
		results = append(results, string(current))
	}
	return results
}

func CountNonEmptyCategories(categories map[string][]string) int {
	count := 0
	for _, items := range categories {
		if len(items) > 0 {
			count++
		}
	}
	return count
}

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

// decodeSectionFlags returns human-readable section flags
func (p *PEFile) decodeSectionFlags(flags uint32) string {
	var flagStrs []string
	if flags&pe.IMAGE_SCN_CNT_CODE != 0 {
		flagStrs = append(flagStrs, "CODE")
	}
	if flags&pe.IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
		flagStrs = append(flagStrs, "INITIALIZED_DATA")
	}
	if flags&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
		flagStrs = append(flagStrs, "UNINITIALIZED_DATA")
	}
	if flags&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
		flagStrs = append(flagStrs, "EXECUTABLE")
	}
	if flags&pe.IMAGE_SCN_MEM_READ != 0 {
		flagStrs = append(flagStrs, "READABLE")
	}
	if flags&pe.IMAGE_SCN_MEM_WRITE != 0 {
		flagStrs = append(flagStrs, "WRITABLE")
	}
	if flags&0x10000000 != 0 {
		flagStrs = append(flagStrs, "SHARED")
	}
	if flags&0x02000000 != 0 {
		flagStrs = append(flagStrs, "DISCARDABLE")
	}
	if len(flagStrs) == 0 {
		return "None"
	}
	result := flagStrs[0]
	for i := 1; i < len(flagStrs); i++ {
		result += ", " + flagStrs[i]
	}
	return result
}

func decodeDLLCharacteristics(flags uint16) string {
	var out []string
	if flags&0x0001 != 0 {
		out = append(out, "PROCESS_INIT")
	}
	if flags&0x0002 != 0 {
		out = append(out, "PROCESS_TERM")
	}
	if flags&0x0004 != 0 {
		out = append(out, "THREAD_INIT")
	}
	if flags&0x0008 != 0 {
		out = append(out, "THREAD_TERM")
	}
	if flags&0x0040 != 0 {
		out = append(out, "DYNAMIC_BASE")
	}
	if flags&0x0080 != 0 {
		out = append(out, "FORCE_INTEGRITY")
	}
	if flags&0x0100 != 0 {
		out = append(out, "NX_COMPAT")
	}
	if flags&0x0200 != 0 {
		out = append(out, "NO_ISOLATION")
	}
	if flags&0x0400 != 0 {
		out = append(out, "NO_SEH")
	}
	if flags&0x0800 != 0 {
		out = append(out, "NO_BIND")
	}
	if flags&0x1000 != 0 {
		out = append(out, "APPCONTAINER")
	}
	if flags&0x2000 != 0 {
		out = append(out, "WDM_DRIVER")
	}
	if flags&0x4000 != 0 {
		out = append(out, "GUARD_CF")
	}
	if flags&0x8000 != 0 {
		out = append(out, "TERMINAL_SERVER_AWARE")
	}
	if len(out) == 0 {
		return "None"
	}
	return strings.Join(out, ", ")
}

func getSubsystemName(subsystem uint16) string {
	switch subsystem {
	case 1:
		return "Native"
	case 2:
		return "Windows GUI"
	case 3:
		return "Windows Console"
	case 5:
		return "OS/2 Console"
	case 7:
		return "POSIX Console"
	case 8:
		return "Native Win9x Driver"
	case 9:
		return "Windows CE GUI"
	case 10:
		return "EFI Application"
	case 11:
		return "EFI Boot Service Driver"
	case 12:
		return "EFI Runtime Driver"
	case 13:
		return "EFI ROM"
	case 14:
		return "Xbox"
	case 16:
		return "Windows Boot Application"
	default:
		return "Unknown"
	}
}

type PEOffsets struct {
	ELfanew          int64
	OptionalHeader   int64
	FirstSectionHdr  int64
	NumberOfSections int
	OptionalHdrSize  int
}

func (p *PEFile) calculateOffsets() (*PEOffsets, error) {
	const (
		dosHeaderSize   = 0x40
		peSignatureSize = 4
		coffHeaderSize  = 20
	)

	if len(p.RawData) < dosHeaderSize {
		return nil, fmt.Errorf("file too small for DOS header")
	}

	offsets := &PEOffsets{
		ELfanew: int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40])),
	}

	coffHeaderOffset := offsets.ELfanew + peSignatureSize
	offsets.OptionalHeader = coffHeaderOffset + coffHeaderSize

	// Validate we can read COFF header fields
	if int(coffHeaderOffset+coffHeaderSize) > len(p.RawData) {
		return nil, fmt.Errorf("file too small for COFF header")
	}

	offsets.NumberOfSections = int(binary.LittleEndian.Uint16(p.RawData[coffHeaderOffset+2 : coffHeaderOffset+4]))
	offsets.OptionalHdrSize = int(binary.LittleEndian.Uint16(p.RawData[coffHeaderOffset+16 : coffHeaderOffset+18]))
	offsets.FirstSectionHdr = offsets.OptionalHeader + int64(offsets.OptionalHdrSize)

	return offsets, nil
}

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

func (p *PEFile) IsExecutableOrShared() bool {
	if p.PE == nil {
		return false
	}
	c := p.PE.FileHeader.Characteristics
	return (c&pe.IMAGE_FILE_EXECUTABLE_IMAGE) != 0 || (c&pe.IMAGE_FILE_DLL) != 0
}

// --- Section Type Utilities ---

func (p *PEFile) validateOffset(offset int64, size int) error {
	if int(offset+int64(size)) > len(p.RawData) {
		return fmt.Errorf("offset %d + size %d exceeds file size %d", offset, size, len(p.RawData))
	}
	return nil
}

func (p *PEFile) CalculatePhysicalFileSize() (uint64, error) {
	if p.PE == nil {
		return 0, fmt.Errorf("PE file not initialized")
	}

	maxSize := uint64(p.SizeOfHeaders())
	for _, s := range p.Sections {
		if s.Size > 0 {
			end := uint64(s.Offset) + uint64(s.Size)
			if end > maxSize {
				maxSize = end
			}
		}
	}

	return maxSize, nil
}
