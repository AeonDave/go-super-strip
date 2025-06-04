package elfrw

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// --- Core Helper Functions ---

// IsLittleEndian checks if the ELF file uses little-endian byte order.
func (e *ELFFile) IsLittleEndian() bool {
	return e.RawData[5] == 0x01 // EI_DATA field, 1 for LSB
}

// GetEndian returns the binary.ByteOrder for the ELF file.
func (e *ELFFile) GetEndian() binary.ByteOrder {
	if e.IsLittleEndian() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// ReadBytes reads a slice of bytes from RawData at a given offset.
func (e *ELFFile) ReadBytes(offset uint64, size int) ([]byte, error) {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return nil, fmt.Errorf("read beyond file limits: offset %d, size %d, file size %d",
			offset, size, len(e.RawData))
	}
	result := make([]byte, size)
	copy(result, e.RawData[offset:offset+uint64(size)])
	return result, nil
}

// fillRegion fills a memory region with either zeros or random bytes
func (e *ELFFile) fillRegion(offset uint64, size int, useRandom bool) error {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return fmt.Errorf("write beyond file limits: offset %d, size %d, file size %d",
			offset, size, len(e.RawData))
	}

	if size == 0 {
		return nil
	}

	if useRandom {
		fillBytes := make([]byte, size)
		if _, err := rand.Read(fillBytes); err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
		copy(e.RawData[offset:offset+uint64(size)], fillBytes)
	} else {
		// Zero fill
		for i := uint64(0); i < uint64(size); i++ {
			e.RawData[offset+i] = 0
		}
	}
	return nil
}

// ZeroFill overwrites a region of RawData with zeros.
func (e *ELFFile) ZeroFill(offset uint64, size int) error {
	return e.fillRegion(offset, size, false)
}

// RandomFill overwrites a region of RawData with random bytes.
func (e *ELFFile) RandomFill(offset uint64, size int) error {
	return e.fillRegion(offset, size, true)
}

// --- Section Categories ---

type SectionCategory struct {
	ExactNames              []string
	PrefixNames             []string
	Description             string
	BreaksRuntimeIfStripped bool
}

var sectionCategories = map[string]SectionCategory{
	"symbols": {
		ExactNames:  []string{".symtab"},
		Description: "Symbol tables",
	},
	"strings": {
		ExactNames:  []string{".strtab"},
		Description: "String tables",
	},
	"debug": {
		ExactNames: []string{
			".debug", ".stab", ".stabstr", ".gdb_index", ".line",
			".debug_abbrev", ".debug_addr", ".debug_aranges", ".debug_attr",
			".debug_cu_index", ".debug_frame", ".debug_gnu_pubnames", ".debug_gnu_pubtypes",
			".debug_info", ".debug_line", ".debug_line_str", ".debug_loc", ".debug_loclists",
			".debug_macinfo", ".debug_macro", ".debug_pubnames", ".debug_pubtypes",
			".debug_ranges", ".debug_rnglists", ".debug_str", ".debug_str_offsets",
			".debug_tu_index", ".debug_types",
			".zdebug_abbrev", ".zdebug_aranges", ".zdebug_frame", ".zdebug_info",
			".zdebug_line", ".zdebug_loc", ".zdebug_macinfo", ".zdebug_pubnames",
			".zdebug_pubtypes", ".zdebug_ranges", ".zdebug_str", ".zdebug_loclists",
			".zdebug_rnglists",
		},
		PrefixNames: []string{".debug_", ".zdebug_", ".gnu.debugl"},
		Description: "Debug information",
	},
	"buildinfo": {
		ExactNames: []string{
			".gnu.build.attributes", ".gnu.warning",
			".note.gnu.build-id", ".note.ABI-tag", ".note.gnu.property",
			".comment", ".buildid", ".SUNW_cap", ".SUNW_signature",
		},
		PrefixNames: []string{".note", ".SUNW_", ".ident"},
		Description: "Build information and notes",
	},
	"versioning": {
		ExactNames: []string{
			".gnu.version", ".gnu.version_r", ".gnu.version_d",
		},
		Description:             "Version information sections",
		BreaksRuntimeIfStripped: true,
	},
	"profiling": {
		ExactNames:  []string{".gmon", ".profile"},
		Description: "Profiling data",
	},
	"exceptions": {
		ExactNames:              []string{".eh_frame", ".eh_frame_hdr", ".gcc_except_table", ".ARM.exidx", ".ARM.extab"},
		PrefixNames:             []string{".pdr", ".mdebug"},
		Description:             "Exception handling and stack unwinding",
		BreaksRuntimeIfStripped: true,
	},
	"arch": {
		PrefixNames: []string{".ARM.", ".MIPS.", ".xtensa."},
		Description: "Architecture-specific sections",
	},
	"relocations": {
		PrefixNames:             []string{".rel.", ".rela."},
		Description:             "Relocation sections",
		BreaksRuntimeIfStripped: true,
	},
	"dynamic": {
		ExactNames: []string{
			".dynamic", ".dynsym", ".dynstr", ".interp", ".hash", ".gnu.hash",
			".got", ".got.plt", ".plt", ".plt.got", ".plt.sec",
		},
		Description:             "Dynamic linking sections",
		BreaksRuntimeIfStripped: true,
	},
}

// --- Core Stripping Logic ---

// matchSectionName checks if a section name matches any of the given patterns
func matchSectionName(sectionName string, exactNames, prefixNames []string) bool {
	// Check exact matches
	for _, name := range exactNames {
		if name != "" && sectionName == name {
			return true
		}
	}

	// Check prefix matches
	for _, prefix := range prefixNames {
		if prefix != "" && strings.HasPrefix(sectionName, prefix) {
			return true
		}
	}

	return false
}

// stripSectionData fills section data and marks it as stripped
func (e *ELFFile) stripSectionData(sectionIndex int, useRandom bool) error {
	section := &e.Sections[sectionIndex]

	if section.Offset <= 0 || section.Size <= 0 {
		return nil // Already stripped or no content
	}

	// Validate section bounds
	if section.Offset >= uint64(len(e.RawData)) {
		return fmt.Errorf("section '%s' offset (%d) out of bounds (%d)",
			section.Name, section.Offset, len(e.RawData))
	}

	// Cap size if it would extend beyond file boundary
	size := section.Size
	if section.Offset+size > uint64(len(e.RawData)) {
		size = uint64(len(e.RawData)) - section.Offset
	}

	// Fill the section data
	if err := e.fillRegion(section.Offset, int(size), useRandom); err != nil {
		return fmt.Errorf("failed to fill section %s: %w", section.Name, err)
	}

	// Mark section as stripped
	section.Offset = 0
	section.Size = 0

	return nil
}

// StripSectionsByCategory strips sections by their category
func (e *ELFFile) StripSectionsByCategory(categoryName string, useRandom bool) error {
	if err := e.validateELF(); err != nil {
		return fmt.Errorf("ELF validation failed: %w", err)
	}

	category, exists := sectionCategories[categoryName]
	if !exists {
		return fmt.Errorf("unknown section category: %s", categoryName)
	}

	strippedCount := 0
	for i, section := range e.Sections {
		if matchSectionName(section.Name, category.ExactNames, category.PrefixNames) {
			if err := e.stripSectionData(i, useRandom); err != nil {
				return err
			}
			strippedCount++
		}
	}

	// Update section headers after modification
	return e.UpdateSectionHeaders()
}

// StripSectionsByNames processes sections based on name match (exact or prefix).
func (e *ELFFile) StripSectionsByNames(names []string, usePrefix, useRandom bool) error {
	if err := e.validateELF(); err != nil {
		return fmt.Errorf("ELF validation failed: %w", err)
	}

	if len(names) == 0 {
		return fmt.Errorf("no section names provided for stripping")
	}

	strippedCount := 0
	for i, section := range e.Sections {
		var exactNames, prefixNames []string
		if usePrefix {
			prefixNames = names
		} else {
			exactNames = names
		}

		if matchSectionName(section.Name, exactNames, prefixNames) {
			if err := e.stripSectionData(i, useRandom); err != nil {
				return err
			}
			strippedCount++
		}
	}

	return e.UpdateSectionHeaders()
}

// StripByteRegex overwrites byte patterns matching a regex in all sections.
func (e *ELFFile) StripByteRegex(pattern *regexp.Regexp, useRandom bool) (int, error) {
	if pattern == nil {
		return 0, fmt.Errorf("regex pattern cannot be nil")
	}

	// If there are no sections, fallback to raw data stripping
	if len(e.Sections) == 0 {
		// Apply regex to entire file
		matches := pattern.FindAllIndex(e.RawData, -1)
		total := 0
		for _, match := range matches {
			start, end := match[0], match[1]
			if start < 0 || end > len(e.RawData) || start >= end {
				continue
			}
			for k := start; k < end; k++ {
				if useRandom {
					b := make([]byte, 1)
					if _, err := rand.Read(b); err == nil {
						e.RawData[k] = b[0]
					} else {
						e.RawData[k] = 0
					}
				} else {
					e.RawData[k] = 0
				}
			}
			total++
		}
		return total, nil
	}

	totalMatches := 0
	for _, section := range e.Sections {
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}

		// Validate and cap section bounds
		if section.Offset >= uint64(len(e.RawData)) {
			continue
		}

		readSize := section.Size
		if section.Offset+readSize > uint64(len(e.RawData)) {
			readSize = uint64(len(e.RawData)) - section.Offset
			if readSize == 0 {
				continue
			}
		}

		sectionData := e.RawData[section.Offset : section.Offset+readSize]
		matches := pattern.FindAllIndex(sectionData, -1)

		for _, match := range matches {
			start, end := match[0], match[1]
			if start < 0 || end > len(sectionData) || start >= end {
				continue
			}

			// Fill matched bytes
			for k := start; k < end; k++ {
				if useRandom {
					b := make([]byte, 1)
					if _, err := rand.Read(b); err == nil {
						sectionData[k] = b[0]
					} else {
						sectionData[k] = 0 // Fallback to zero on error
					}
				} else {
					sectionData[k] = 0
				}
			}
			totalMatches++
		}
	}

	return totalMatches, nil
}

// --- Header and Segment Operations ---

// StripSectionTable removes references to the section header table from the ELF header.
func (e *ELFFile) StripSectionTable() error {
	shoffPos, shNumPos, shStrNdxPos := e.getHeaderPositions()

	// Zero out section header table references
	if e.Is64Bit {
		if err := e.writeAtOffset(shoffPos, uint64(0)); err != nil {
			return fmt.Errorf("failed to zero e_shoff (64-bit): %w", err)
		}
	} else {
		if err := e.writeAtOffset(shoffPos, uint32(0)); err != nil {
			return fmt.Errorf("failed to zero e_shoff (32-bit): %w", err)
		}
	}

	if err := e.writeAtOffset(shNumPos, uint16(0)); err != nil {
		return fmt.Errorf("failed to zero e_shnum: %w", err)
	}

	if err := e.writeAtOffset(shStrNdxPos, uint16(0)); err != nil {
		return fmt.Errorf("failed to zero e_shstrndx: %w", err)
	}

	return nil
}

// StripNonLoadableSegments zeros out data and metadata for non-PT_LOAD segments.
func (e *ELFFile) StripNonLoadableSegments(useRandom bool) error {
	for i, segment := range e.Segments {
		if segment.Loadable {
			continue
		}

		if segment.Offset > 0 && segment.Size > 0 {
			if err := e.fillRegion(segment.Offset, int(segment.Size), useRandom); err != nil {
				return fmt.Errorf("failed to fill non-loadable segment %d: %w", i, err)
			}
		}

		// Mark segment as stripped
		e.Segments[i].Offset = 0
		e.Segments[i].Size = 0
	}

	return e.UpdateProgramHeaders()
}

// --- High-Level Stripping Functions ---

// StripDebugSections removes debugging information.
func (e *ELFFile) StripDebugSections(useRandom bool) error {
	return e.StripSectionsByCategory("debug", useRandom)
}

// StripSymbolTables removes symbol table sections.
func (e *ELFFile) StripSymbolTables(useRandom bool) error {
	return e.StripSectionsByCategory("symbols", useRandom)
}

// StripStringTables removes general string table sections.
func (e *ELFFile) StripStringTables(useRandom bool) error {
	return e.StripSectionsByCategory("strings", useRandom)
}

// StripBuildInfoSections removes build information sections.
func (e *ELFFile) StripBuildInfoSections(useRandom bool) error {
	return e.StripSectionsByCategory("buildinfo", useRandom)
}

// StripProfilingSections removes profiling related sections.
func (e *ELFFile) StripProfilingSections(useRandom bool) error {
	return e.StripSectionsByCategory("profiling", useRandom)
}

// StripExceptionSections removes exception handling sections.
// WARNING: This can break C++ exception handling and debugger stack unwinding.
func (e *ELFFile) StripExceptionSections(useRandom bool) error {
	return e.StripSectionsByCategory("exceptions", useRandom)
}

// StripArchSections removes architecture-specific sections.
func (e *ELFFile) StripArchSections(useRandom bool) error {
	return e.StripSectionsByCategory("arch", useRandom)
}

// StripRelocationSections removes relocation sections.
// WARNING: This will break dynamically linked executables.
func (e *ELFFile) StripRelocationSections(useRandom bool) error {
	return e.StripSectionsByCategory("relocations", useRandom)
}

// StripDynamicLinkingData removes sections critical for dynamic linking.
// WARNING: This will break dynamically linked executables.
func (e *ELFFile) StripDynamicLinkingData(useRandom bool) error {
	if err := e.StripSectionsByCategory("dynamic", useRandom); err != nil {
		return fmt.Errorf("stripping dynamic linking sections: %w", err)
	}
	// Also strip relocations as they are tightly coupled
	if err := e.StripRelocationSections(useRandom); err != nil {
		return fmt.Errorf("stripping relocations during dynamic linking strip: %w", err)
	}
	return nil
}

// StripAllMetadata removes a wide range of non-essential metadata.
// This is a safer version that preserves critical sections for dynamic linking.
func (e *ELFFile) StripAllMetadata(useRandom bool) error {
	// Define stripping operations in order of safety (safest first)
	// Note: We do NOT strip the section table to preserve runtime functionality
	operations := []struct {
		name string
		fn   func(bool) error
	}{
		{"debug sections", e.StripDebugSections},
		{"symbol tables", e.StripSymbolTables},
		{"build info", e.StripBuildInfoSections},
		{"profiling", e.StripProfilingSections},
		// Skip exception sections and arch sections for better compatibility
		// Skip string tables as they may contain essential dynamic linking strings
	}

	// Execute each operation
	for _, op := range operations {
		if err := op.fn(useRandom); err != nil {
			return fmt.Errorf("%s stripping failed: %w", op.name, err)
		}
	}

	return nil
}

// GetSectionCategories returns information about available section categories
func GetSectionCategories() map[string]SectionCategory {
	// Return a copy to prevent external modification
	result := make(map[string]SectionCategory)
	for k, v := range sectionCategories {
		result[k] = v
	}
	return result
}
