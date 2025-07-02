package elfrw

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
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
	return common.MatchesPattern(sectionName, exactNames, prefixNames)
}

// stripSectionData fills section data and marks it as stripped
func (e *ELFFile) stripSectionData(sectionIndex int, useRandom bool) error {
	section := &e.Sections[sectionIndex]

	if section.Offset <= 0 || section.Size <= 0 {
		return nil // Already stripped or no content
	}

	// Validate section bounds
	if uint64(section.Offset) >= uint64(len(e.RawData)) {
		return fmt.Errorf("section '%s' offset (%d) out of bounds (%d)",
			section.Name, section.Offset, len(e.RawData))
	}

	// Cap size if it would extend beyond file boundary
	size := section.Size
	if uint64(section.Offset)+uint64(size) > uint64(len(e.RawData)) {
		size = int64(uint64(len(e.RawData)) - uint64(section.Offset))
	}

	// Fill the section data
	if err := e.fillRegion(uint64(section.Offset), int(size), useRandom); err != nil {
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

// StripSectionsByCategoryDetailed strips sections by their category with detailed result
func (e *ELFFile) StripSectionsByCategoryDetailed(categoryName string, useRandom bool) *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	category, exists := sectionCategories[categoryName]
	if !exists {
		return common.NewSkipped(fmt.Sprintf("unknown section category: %s", categoryName))
	}

	strippedSections := []string{}
	for i, section := range e.Sections {
		if matchSectionName(section.Name, category.ExactNames, category.PrefixNames) {
			if err := e.stripSectionData(i, useRandom); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to strip section %s: %v", section.Name, err))
			}
			strippedSections = append(strippedSections, section.Name)
		}
	}

	if len(strippedSections) == 0 {
		return common.NewSkipped(fmt.Sprintf("no %s sections found", category.Description))
	}

	// Update section headers after modification
	if err := e.UpdateSectionHeaders(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to update section headers: %v", err))
	}

	message := fmt.Sprintf("stripped %s sections: %s", category.Description, strings.Join(strippedSections, ", "))
	return common.NewApplied(message, len(strippedSections))
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
		if uint64(section.Offset) >= uint64(len(e.RawData)) {
			continue
		}

		readSize := section.Size
		if uint64(section.Offset)+uint64(readSize) > uint64(len(e.RawData)) {
			readSize = int64(uint64(len(e.RawData)) - uint64(section.Offset))
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

		if segment.Offset > 0 && segment.FileSize > 0 {
			if err := e.fillRegion(segment.Offset, int(segment.FileSize), useRandom); err != nil {
				return fmt.Errorf("failed to fill non-loadable segment %d: %w", i, err)
			}
		}

		// Mark segment as stripped
		e.Segments[i].Offset = 0
		e.Segments[i].FileSize = 0
	}

	return e.UpdateProgramHeaders()
}

// --- High-Level Stripping Functions ---

// StripDebugSections removes debugging information.
func (e *ELFFile) StripDebugSections(useRandom bool) *common.OperationResult {
	return e.StripSectionsByCategoryDetailed("debug", useRandom)
}

// StripSymbolTables removes symbol table sections.
func (e *ELFFile) StripSymbolTables(useRandom bool) *common.OperationResult {
	return e.StripSectionsByCategoryDetailed("symbols", useRandom)
}

// StripStringTables removes general string table sections.
func (e *ELFFile) StripStringTables(useRandom bool) *common.OperationResult {
	return e.StripSectionsByCategoryDetailed("strings", useRandom)
}

// StripBuildInfoSections removes build information sections.
func (e *ELFFile) StripBuildInfoSections(useRandom bool) *common.OperationResult {
	return e.StripSectionsByCategoryDetailed("buildinfo", useRandom)
}

// StripProfilingSections removes profiling related sections.
func (e *ELFFile) StripProfilingSections(useRandom bool) *common.OperationResult {
	return e.StripSectionsByCategoryDetailed("profiling", useRandom)
}

// StripExceptionSections removes exception handling sections.
// WARNING: This can break C++ exception handling and debugger stack unwinding.
func (e *ELFFile) StripExceptionSections(useRandom bool) *common.OperationResult {
	return e.StripSectionsByCategoryDetailed("exceptions", useRandom)
}

// StripArchSections removes architecture-specific sections.
func (e *ELFFile) StripArchSections(useRandom bool) *common.OperationResult {
	return e.StripSectionsByCategoryDetailed("arch", useRandom)
}

// StripRelocationSections removes relocation sections.
// WARNING: This will break dynamically linked executables.
func (e *ELFFile) StripRelocationSections(useRandom bool) *common.OperationResult {
	return e.StripSectionsByCategoryDetailed("relocations", useRandom)
}

// StripDynamicLinkingData removes sections critical for dynamic linking.
// WARNING: This will break dynamically linked executables.
func (e *ELFFile) StripDynamicLinkingData(useRandom bool) *common.OperationResult {
	dynamicResult := e.StripSectionsByCategoryDetailed("dynamic", useRandom)
	if !dynamicResult.Applied {
		// If dynamic sections weren't stripped, still try relocations
		relResult := e.StripRelocationSections(useRandom)
		if relResult.Applied {
			return common.NewApplied(fmt.Sprintf("dynamic sections skipped, but %s", relResult.Message), relResult.Count)
		}
		return common.NewSkipped("no dynamic linking or relocation sections found")
	}

	// Also strip relocations as they are tightly coupled
	relResult := e.StripRelocationSections(useRandom)
	totalCount := dynamicResult.Count + relResult.Count

	if relResult.Applied {
		return common.NewApplied(fmt.Sprintf("%s; %s", dynamicResult.Message, relResult.Message), totalCount)
	}
	return common.NewApplied(dynamicResult.Message, dynamicResult.Count)
}

// StripAllMetadata removes a wide range of non-essential metadata.
// This is a safer version that preserves critical sections for dynamic linking.
func (e *ELFFile) StripAllMetadata(useRandom bool) *common.OperationResult {
	// Define stripping operations in order of safety (safest first)
	// Note: We do NOT strip the section table to preserve runtime functionality
	operations := []struct {
		name string
		fn   func(bool) *common.OperationResult
	}{
		{"debug sections", e.StripDebugSections},
		{"symbol tables", e.StripSymbolTables},
		{"build info sections", e.StripBuildInfoSections},
		{"profiling sections", e.StripProfilingSections},
		// Skip exception sections and arch sections for better compatibility
		// Skip string tables as they may contain essential dynamic linking strings
	}

	appliedOperations := []string{}
	totalCount := 0

	// Execute each operation
	for _, op := range operations {
		result := op.fn(useRandom)
		if result.Applied {
			appliedOperations = append(appliedOperations, result.Message)
			totalCount += result.Count
		}
	}

	if len(appliedOperations) == 0 {
		return common.NewSkipped("no metadata sections found to strip")
	}

	message := fmt.Sprintf("stripped metadata: %s", strings.Join(appliedOperations, "; "))
	return common.NewApplied(message, totalCount)
}

// FixSectionHeaderIntegrity ensures section header table is valid after stripping operations.
// This prevents issues with tools like UPX that validate e_shoff.
func (e *ELFFile) FixSectionHeaderIntegrity() error {
	if err := e.validateELF(); err != nil {
		return fmt.Errorf("ELF validation failed: %w", err)
	}

	shoffPos, shNumPos, shStrNdxPos := e.getHeaderPositions()
	sectionHeaderOffset := e.getSectionHeaderOffset(shoffPos)

	// If section header offset is beyond file bounds or invalid, zero it out
	if sectionHeaderOffset >= uint64(len(e.RawData)) || sectionHeaderOffset == 0 {
		return e.clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos)
	}

	// Calculate expected section header table size
	shNum := e.readUint16(shNumPos)
	var entrySize uint64
	if e.Is64Bit {
		entrySize = uint64(e.readUint16(58)) // e_shentsize for 64-bit
	} else {
		entrySize = uint64(e.readUint16(46)) // e_shentsize for 32-bit
	}

	expectedTableSize := uint64(shNum) * entrySize

	// If section header table would extend beyond file, zero out the header references
	if sectionHeaderOffset+expectedTableSize > uint64(len(e.RawData)) {
		return e.clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos)
	}

	// Validate that each section header entry is within bounds
	for i := uint16(0); i < shNum; i++ {
		headerPos := sectionHeaderOffset + uint64(i)*entrySize
		if headerPos+entrySize > uint64(len(e.RawData)) {
			// If any section header is out of bounds, zero the entire table
			return e.clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos)
		}
	}

	return nil
}

// FixSectionHeaderIntegrityWithSize ensures section header table is valid for a specific file size.
// This is used during commit to prevent issues with tools like UPX after file truncation.
func (e *ELFFile) FixSectionHeaderIntegrityWithSize(newFileSize uint64) error {
	if err := e.validateELF(); err != nil {
		return fmt.Errorf("ELF validation failed: %w", err)
	}

	shoffPos, shNumPos, shStrNdxPos := e.getHeaderPositions()
	sectionHeaderOffset := e.getSectionHeaderOffset(shoffPos)

	// If section header offset is beyond new file bounds or invalid, zero it out
	if sectionHeaderOffset >= newFileSize || sectionHeaderOffset == 0 {
		return e.clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos)
	}

	// Calculate expected section header table size
	shNum := e.readUint16(shNumPos)
	var entrySize uint64
	if e.Is64Bit {
		entrySize = uint64(e.readUint16(58)) // e_shentsize for 64-bit
	} else {
		entrySize = uint64(e.readUint16(46)) // e_shentsize for 32-bit
	}

	expectedTableSize := uint64(shNum) * entrySize

	// If section header table would extend beyond new file size, zero out the header references
	if sectionHeaderOffset+expectedTableSize > newFileSize {
		return e.clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos)
	}

	// Validate that each section header entry is within new file bounds
	for i := uint16(0); i < shNum; i++ {
		headerPos := sectionHeaderOffset + uint64(i)*entrySize
		if headerPos+entrySize > newFileSize {
			// If any section header is out of bounds, zero the entire table
			return e.clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos)
		}
	}

	return nil
}

// clearSectionHeaders helper function (moved from write.go for better access)
func (e *ELFFile) clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos int) error {
	if err := e.writeAtOffset(shoffPos, uint64(0)); err != nil {
		return err
	}
	if err := e.writeAtOffset(shNumPos, uint16(0)); err != nil {
		return err
	}
	return e.writeAtOffset(shStrNdxPos, uint16(0))
}

// getHeaderPositions helper function (moved from write.go for better access)
func (e *ELFFile) getHeaderPositions() (int, int, int) {
	if e.Is64Bit {
		return 40, 60, 62 // e_shoff, e_shnum, e_shstrndx for 64-bit
	}
	return 32, 48, 50 // e_shoff, e_shnum, e_shstrndx for 32-bit
}

// getSectionHeaderOffset helper function (moved from write.go for better access)
func (e *ELFFile) getSectionHeaderOffset(shoffPos int) uint64 {
	if e.Is64Bit {
		return e.readUint64(shoffPos)
	}
	return uint64(e.readUint32(shoffPos))
}

// Helper methods for reading/writing values (moved from write.go for better access)
func (e *ELFFile) readUint64(pos int) uint64 {
	if e.RawData[5] == 1 {
		return binary.LittleEndian.Uint64(e.RawData[pos : pos+8])
	}
	return binary.BigEndian.Uint64(e.RawData[pos : pos+8])
}

func (e *ELFFile) readUint32(pos int) uint32 {
	if e.RawData[5] == 1 {
		return binary.LittleEndian.Uint32(e.RawData[pos : pos+4])
	}
	return binary.BigEndian.Uint32(e.RawData[pos : pos+4])
}

func (e *ELFFile) readUint16(pos int) uint16 {
	if e.RawData[5] == 1 {
		return binary.LittleEndian.Uint16(e.RawData[pos : pos+2])
	}
	return binary.BigEndian.Uint16(e.RawData[pos : pos+2])
}

func (e *ELFFile) writeAtOffset(pos int, value interface{}) error {
	var size int
	switch value.(type) {
	case uint16:
		size = 2
	case uint32:
		size = 4
	case uint64:
		size = 8
	default:
		size = len(e.RawData) - pos
	}
	if pos < 0 || pos+size > len(e.RawData) {
		return fmt.Errorf("offset out of bounds: %d (size %d)", pos, size)
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, e.GetEndian(), value); err != nil {
		return fmt.Errorf("failed to write value: %w", err)
	}
	copy(e.RawData[pos:], buf.Bytes())
	return nil
}

// --- Advanced Stripping and Compaction ---

// CompactAndStrip performs aggressive stripping with actual file size reduction
// This implements functionality similar to sstrip for maximum size reduction
func (e *ELFFile) CompactAndStrip(removeNonEssential bool) (*common.OperationResult, error) {
	if err := e.validateELF(); err != nil {
		return nil, fmt.Errorf("ELF validation failed: %w", err)
	}

	originalSize := uint64(len(e.RawData))

	// Step 1: Calculate minimum required file size based on program headers
	newSize, err := e.calculateMinimumFileSize()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate minimum file size: %w", err)
	}

	// Step 2: Remove non-essential sections if requested
	removedSections := []string{}
	if removeNonEssential {
		removed := e.removeNonEssentialSections()
		removedSections = append(removedSections, removed...)
	}

	// Step 3: Truncate trailing zeros if they exist
	newSize = e.truncateTrailingZeros(newSize)

	// Step 4: Update headers to reflect new file size
	if err := e.modifyHeadersForSize(newSize); err != nil {
		return nil, fmt.Errorf("failed to modify headers: %w", err)
	}

	// Step 5: Truncate the file
	e.RawData = e.RawData[:newSize]

	savedBytes := originalSize - newSize
	percentage := float64(savedBytes) * 100.0 / float64(originalSize)

	message := fmt.Sprintf("compacted file: %d -> %d bytes (%.1f%% reduction)",
		originalSize, newSize, percentage)

	if len(removedSections) > 0 {
		message += fmt.Sprintf(", removed sections: %s", strings.Join(removedSections, ", "))
	}

	return common.NewApplied(message, int(savedBytes)), nil
}

// calculateMinimumFileSize determines the minimum file size needed based on program headers
// This is similar to getmemorysize() in sstrip.c
func (e *ELFFile) calculateMinimumFileSize() (uint64, error) {
	// Start with ELF header size
	headerSize := uint64(64) // 64-bit ELF header
	if !e.Is64Bit {
		headerSize = 52 // 32-bit ELF header
	}

	// Include program header table
	phdrSize := uint64(0)
	if len(e.Segments) > 0 {
		phdrEntrySize := uint64(56) // 64-bit program header entry
		if !e.Is64Bit {
			phdrEntrySize = 32 // 32-bit program header entry
		}

		// Calculate program header table offset and size
		phdrOffset := e.readProgramHeaderOffset()
		phdrSize = phdrOffset + uint64(len(e.Segments))*phdrEntrySize
	}

	minSize := headerSize
	if phdrSize > minSize {
		minSize = phdrSize
	}

	// Include all data referenced by loadable segments
	for _, segment := range e.Segments {
		if segment.Type == 1 { // PT_LOAD
			segmentEnd := segment.Offset + segment.FileSize
			if segmentEnd > minSize {
				minSize = segmentEnd
			}
		}
	}

	return minSize, nil
}

// removeNonEssentialSections removes sections that are not needed for execution
func (e *ELFFile) removeNonEssentialSections() []string {
	removed := []string{}

	// Categories of sections that can be safely removed
	safeToRemove := []string{"debug", "symbols", "strings", "buildinfo", "profiling"}

	for _, category := range safeToRemove {
		if cat, exists := sectionCategories[category]; exists {
			for i := len(e.Sections) - 1; i >= 0; i-- {
				section := e.Sections[i]
				if matchSectionName(section.Name, cat.ExactNames, cat.PrefixNames) {
					// Skip critical sections like .shstrtab
					if section.Name == ".shstrtab" {
						continue
					}
					removed = append(removed, section.Name)
					// Remove section from slice
					e.Sections = append(e.Sections[:i], e.Sections[i+1:]...)
				}
			}
		}
	}

	return removed
}

// truncateTrailingZeros removes trailing zero bytes from the end of the file
func (e *ELFFile) truncateTrailingZeros(size uint64) uint64 {
	if size == 0 || size > uint64(len(e.RawData)) {
		return size
	}

	// Scan backwards from the proposed end to find last non-zero byte
	for size > 0 && e.RawData[size-1] == 0 {
		size--
	}

	// Sanity check - don't truncate to nothing
	if size == 0 {
		size = 64 // Minimum ELF header size
	}

	return size
}

// modifyHeadersForSize updates ELF headers for the new file size
// This is similar to modifyheaders() in sstrip.c
func (e *ELFFile) modifyHeadersForSize(newSize uint64) error {
	// If section header table is beyond new size, remove references to it
	shOffset := e.readSectionHeaderOffset()
	if shOffset >= newSize {
		if err := e.StripSectionTable(); err != nil {
			return fmt.Errorf("failed to strip section table: %w", err)
		}
	}

	// Update program headers that extend beyond new file size
	phdrOffset := e.readProgramHeaderOffset()
	phdrEntrySize := uint64(56) // 64-bit
	if !e.Is64Bit {
		phdrEntrySize = 32 // 32-bit
	}

	for i, segment := range e.Segments {
		phdrPos := phdrOffset + uint64(i)*phdrEntrySize

		if segment.Offset >= newSize {
			// Segment is completely beyond new file size - zero it out
			e.Segments[i].Offset = newSize
			e.Segments[i].FileSize = 0

			// Update in raw data
			err := e.writeProgramHeaderEntry(phdrPos, e.Segments[i])
			if err != nil {
				return err
			}
		} else if segment.Offset+segment.FileSize > newSize {
			// Segment extends beyond new file size - truncate it
			e.Segments[i].FileSize = newSize - segment.Offset

			// Update in raw data
			err := e.writeProgramHeaderEntry(phdrPos, e.Segments[i])
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Helper functions for reading header offsets
func (e *ELFFile) readProgramHeaderOffset() uint64 {
	if e.Is64Bit {
		return e.readUint64(32) // e_phoff for 64-bit
	}
	return uint64(e.readUint32(28)) // e_phoff for 32-bit
}

func (e *ELFFile) readSectionHeaderOffset() uint64 {
	if e.Is64Bit {
		return e.readUint64(40) // e_shoff for 64-bit
	}
	return uint64(e.readUint32(32)) // e_shoff for 32-bit
}

// writeProgramHeaderEntry updates a program header entry in raw data
func (e *ELFFile) writeProgramHeaderEntry(offset uint64, segment Segment) error {
	if offset+56 > uint64(len(e.RawData)) { // 64-bit header size
		return fmt.Errorf("program header offset out of bounds")
	}

	endian := e.GetEndian()

	if e.Is64Bit {
		// Write p_offset (64-bit)
		endian.PutUint64(e.RawData[offset+8:], segment.Offset)
		// Write p_filesz (64-bit)
		endian.PutUint64(e.RawData[offset+32:], segment.FileSize)
	} else {
		// 32-bit program header
		if offset+32 > uint64(len(e.RawData)) {
			return fmt.Errorf("32-bit program header offset out of bounds")
		}
		// Write p_offset (32-bit)
		endian.PutUint32(e.RawData[offset+4:], uint32(segment.Offset))
		// Write p_filesz (32-bit)
		endian.PutUint32(e.RawData[offset+16:], uint32(segment.FileSize))
	}

	return nil
}

// AdvancedStripDetailed performs comprehensive stripping with size reduction
func (e *ELFFile) AdvancedStripDetailed(compact bool) *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	originalSize := uint64(len(e.RawData))
	operations := []string{}
	totalCount := 0

	// Step 1: StripAll debug sections (always safe)
	debugResult := e.StripDebugSections(false)
	if debugResult.Applied {
		operations = append(operations, debugResult.Message)
		totalCount += debugResult.Count
	}

	// Step 2: StripAll symbol tables (safe for most executables)
	symbolResult := e.StripSymbolTables(false)
	if symbolResult.Applied {
		operations = append(operations, symbolResult.Message)
		totalCount += symbolResult.Count
	}

	// Step 3: StripAll build info and metadata
	buildInfoResult := e.StripBuildInfoSections(false)
	if buildInfoResult.Applied {
		operations = append(operations, buildInfoResult.Message)
		totalCount += buildInfoResult.Count
	}

	// Note: We no longer perform aggressive stripping (string tables, profiling sections)
	// as these operations can be risky for some executables

	// Step 4: File compaction (if requested)
	if compact {
		compactResult, err := e.CompactAndStrip(false) // Use non-aggressive compaction
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("compaction failed: %v", err))
		}
		if compactResult.Applied {
			operations = append(operations, compactResult.Message)
		}
	}

	if len(operations) == 0 {
		return common.NewSkipped("no stripping operations applied")
	}

	// Calculate final size reduction
	newSize := uint64(len(e.RawData))
	savedBytes := originalSize - newSize
	percentage := float64(savedBytes) * 100.0 / float64(originalSize)

	message := fmt.Sprintf("advanced strip completed: %d -> %d bytes (%.1f%% reduction); %s",
		originalSize, newSize, percentage, strings.Join(operations, "; "))

	return common.NewApplied(message, totalCount)
}

// StripAll strips all sections according to rules similar to PE
func (e *ELFFile) StripAll(force bool) *common.OperationResult {
	originalSize := uint64(len(e.RawData))
	var operations []string
	totalCount := 0

	// Strip debug sections
	debugResult := e.StripDebugSections(force)
	if debugResult != nil && debugResult.Applied {
		operations = append(operations, debugResult.Message)
		totalCount++
	}

	// Strip relocations if force is enabled
	if force {
		relocResult := e.StripRelocationSections(force)
		if relocResult != nil && relocResult.Applied {
			operations = append(operations, relocResult.Message)
			totalCount++
		}
	}

	if totalCount == 0 {
		return common.NewSkipped("No sections were stripped")
	}

	newSize := uint64(len(e.RawData))
	bytesRemoved := originalSize - newSize

	message := fmt.Sprintf("Stripped %d section types", totalCount)
	if len(operations) > 0 {
		message += ": " + strings.Join(operations, ", ")
	}
	if bytesRemoved > 0 {
		message += fmt.Sprintf(" (saved %d bytes)", bytesRemoved)
	}

	return common.NewApplied(message, totalCount)
}

// CommitChanges saves the changes to the file
func (e *ELFFile) CommitChanges(newSize uint64) error {
	if e.File == nil {
		return fmt.Errorf("file is not open")
	}

	// Truncate file to new size if needed
	if newSize < uint64(len(e.RawData)) {
		e.RawData = e.RawData[:newSize]
	}

	// Seek to beginning and write the data
	if _, err := e.File.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to beginning: %w", err)
	}

	if _, err := e.File.Write(e.RawData); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Truncate file to exact size
	if err := e.File.Truncate(int64(newSize)); err != nil {
		return fmt.Errorf("failed to truncate file: %w", err)
	}

	if err := e.File.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	return nil
}
