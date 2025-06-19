package perw

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"gosstrip/common"
	"log"
	"regexp"
	"strings"
)

// --- Core Helper Functions ---

// fillRegion fills a memory region with zeros or random bytes
func (p *PEFile) fillRegion(offset int64, size int, mode common.FillMode) error {
	if offset < 0 || size < 0 || offset+int64(size) > int64(len(p.RawData)) {
		return fmt.Errorf("invalid region: offset %d, size %d, total %d", offset, size, len(p.RawData))
	}

	if size == 0 {
		return nil
	}

	switch mode {
	case common.ZeroFill:
		for i := int64(0); i < int64(size); i++ {
			p.RawData[offset+i] = 0
		}
	case common.RandomFill:
		fillBytes := make([]byte, size)
		if _, err := rand.Read(fillBytes); err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
		copy(p.RawData[offset:offset+int64(size)], fillBytes)
	default:
		return fmt.Errorf("unknown fill mode: %v", mode)
	}
	return nil
}

// --- Core Stripping Logic ---

// StripSectionsByType strips sections based on their type
func (p *PEFile) StripSectionsByType(sectionType common.SectionType, fillMode common.FillMode, force bool) *common.OperationResult {
	return p.StripSectionsByTypeWithObfuscation(sectionType, fillMode, force, false)
}

// StripSectionsByTypeWithObfuscation strips sections based on their type, considering obfuscation needs
func (p *PEFile) StripSectionsByTypeWithObfuscation(sectionType common.SectionType, fillMode common.FillMode, force bool, obfuscationEnabled bool) *common.OperationResult {
	sectionMatchers := common.GetSectionMatchers()
	matcher, exists := sectionMatchers[sectionType]
	if !exists {
		return common.NewSkipped(fmt.Sprintf("unknown section type: %v", sectionType))
	}

	// Check if this is a risky operation and force is not enabled
	if matcher.IsRisky && !force {
		return common.NewSkipped(fmt.Sprintf("%s skipped (risky operation, use -f to force)", matcher.Description))
	}

	// If obfuscation is enabled and this section is needed for obfuscation, skip it
	if obfuscationEnabled && matcher.ObfuscationNeeded {
		return common.NewSkipped(fmt.Sprintf("%s skipped (needed for obfuscation)", matcher.Description))
	}

	// Check if we should strip this type for the current file
	if !p.shouldStripForFileType(sectionType) {
		return common.NewSkipped("not applicable for this file type")
	}

	strippedCount := 0
	var strippedSections []string
	for _, section := range p.Sections {
		if !common.MatchesPattern(section.Name, matcher.ExactNames, matcher.PrefixNames) {
			continue
		}

		if section.Offset > 0 && section.Size > 0 {
			if err := p.fillRegion(section.Offset, int(section.Size), fillMode); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to fill section %s: %v", section.Name, err))
			}
			strippedCount++
			strippedSections = append(strippedSections, section.Name)
		}
	}

	if strippedCount == 0 {
		return common.NewSkipped(fmt.Sprintf("no %s found", matcher.Description))
	}

	message := fmt.Sprintf("stripped %d %s sections (%s)", strippedCount, matcher.Description, strings.Join(strippedSections, ", "))
	return common.NewApplied(message, strippedCount)
}

// StripSectionsByNames strips sections by exact names or prefix matching
func (p *PEFile) StripSectionsByNames(names []string, prefix bool, useRandomFill bool) error {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}

	for _, section := range p.Sections {
		shouldStrip := false

		if prefix {
			for _, name := range names {
				if strings.HasPrefix(section.Name, name) {
					shouldStrip = true
					break
				}
			}
		} else {
			for _, name := range names {
				if section.Name == name {
					shouldStrip = true
					break
				}
			}
		}

		if shouldStrip && section.Offset > 0 && section.Size > 0 {
			if err := p.fillRegion(section.Offset, int(section.Size), fillMode); err != nil {
				return fmt.Errorf("failed to fill section %s: %w", section.Name, err)
			}
		}
	}

	return nil
}

// StripBytePattern overwrites byte patterns matching a regex in sections
func (p *PEFile) StripBytePattern(pattern *regexp.Regexp, fillMode common.FillMode) (int, error) {
	if pattern == nil {
		return 0, fmt.Errorf("regex pattern cannot be nil")
	}

	totalMatches := 0
	for _, section := range p.Sections {
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}

		sectionStart := section.Offset
		sectionEnd := section.Offset + int64(section.Size)

		// Check bounds
		if sectionStart >= int64(len(p.RawData)) || sectionEnd > int64(len(p.RawData)) {
			continue
		}

		sectionData := p.RawData[sectionStart:sectionEnd]
		matches := pattern.FindAllIndex(sectionData, -1)

		for _, match := range matches {
			start := match[0]
			end := match[1]
			if start >= 0 && end <= len(sectionData) {
				if err := p.fillRegion(section.Offset+int64(start), end-start, fillMode); err != nil {
					return totalMatches, fmt.Errorf("failed to fill pattern at section %s offset %d: %w", section.Name, start, err)
				}
				totalMatches++
			}
		}
	}

	return totalMatches, nil
}

// --- Convenience Functions ---

// StripDebugSections strips debug information sections
func (p *PEFile) StripDebugSections(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.DebugSections, fillMode, false)
}

// StripSymbolTables strips symbol table sections
func (p *PEFile) StripSymbolTables(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.SymbolSections, fillMode, false)
}

// StripRelocationTable strips relocation table sections
func (p *PEFile) StripRelocationTable(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.RelocationSections, fillMode, true) // Relocation is always risky
}

// StripNonEssentialSections strips non-essential metadata sections
func (p *PEFile) StripNonEssentialSections(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.NonEssentialSections, fillMode, false)
}

// StripExceptionHandlingData strips exception handling data
func (p *PEFile) StripExceptionHandlingData(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.ExceptionSections, fillMode, true) // Exception handling is risky
}

// StripBuildInfoSections strips build information sections
func (p *PEFile) StripBuildInfoSections(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.BuildInfoSections, fillMode, false)
}

// StripAllMetadata strips all types of metadata from PE file
func (p *PEFile) StripAllMetadata(useRandomFill bool) error {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}

	// List of section types to strip
	sectionTypes := []common.SectionType{
		common.DebugSections,
		common.SymbolSections,
		common.NonEssentialSections,
		common.BuildInfoSections,
	}

	for _, sectionType := range sectionTypes {
		result := p.StripSectionsByType(sectionType, fillMode, false)
		if result != nil && result.Applied {
			log.Printf("Stripped: %s", result.Message)
		}
	}

	// Handle relocation sections separately (risky operation)
	result := p.StripSectionsByType(common.RelocationSections, fillMode, true)
	if result != nil && result.Applied {
		log.Printf("WARNING: Stripped relocation sections (risky): %s", result.Message)
	}

	return nil
}

// --- Main Strip and Compact Functions ---

// CompactAndStripPE performs aggressive PE stripping with actual file size reduction
func (p *PEFile) CompactAndStripPE(removeNonEssential bool) (*common.OperationResult, error) {
	originalSize := uint64(len(p.RawData))
	operations := []string{}
	totalCount := 0
	// Strip debug sections (always safe)
	debugResult := p.StripSectionsByType(common.DebugSections, common.ZeroFill, false)
	if debugResult != nil && debugResult.Applied {
		operations = append(operations, debugResult.Message)
		totalCount += debugResult.Count
	}

	// Strip build info and non-essential sections if requested
	if removeNonEssential {
		buildInfoResult := p.StripSectionsByType(common.BuildInfoSections, common.ZeroFill, false)
		if buildInfoResult != nil && buildInfoResult.Applied {
			operations = append(operations, buildInfoResult.Message)
			totalCount += buildInfoResult.Count
		}

		nonEssentialResult := p.StripSectionsByType(common.NonEssentialSections, common.ZeroFill, false)
		if nonEssentialResult != nil && nonEssentialResult.Applied {
			operations = append(operations, nonEssentialResult.Message)
			totalCount += nonEssentialResult.Count
		}
	}

	// Perform simple truncation compaction
	compactResult, err := p.SimpleTruncationPE()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("compaction failed: %v", err)), nil
	}
	if compactResult.Applied {
		operations = append(operations, compactResult.Message)
	}

	if len(operations) == 0 {
		return common.NewSkipped("no stripping or compaction operations applied"), nil
	}

	newSize := uint64(len(p.RawData))
	savedBytes := originalSize - newSize
	percentage := float64(savedBytes) * 100.0 / float64(originalSize)

	message := fmt.Sprintf("PE strip+compact: %d -> %d bytes (%.1f%% reduction); %s",
		originalSize, newSize, percentage, strings.Join(operations, "; "))

	return common.NewApplied(message, totalCount), nil
}

// AdvancedStripPEDetailed performs comprehensive PE stripping
func (p *PEFile) AdvancedStripPEDetailed(compact bool, force bool) *common.OperationResult {
	originalSize := uint64(len(p.RawData))
	operations := []string{}
	totalCount := 0
	// Strip debug sections (always safe)
	debugResult := p.StripSectionsByType(common.DebugSections, common.ZeroFill, false)
	if debugResult != nil && debugResult.Applied {
		operations = append(operations, debugResult.Message)
		totalCount += debugResult.Count
	}

	// Strip build info and metadata
	buildInfoResult := p.StripSectionsByType(common.BuildInfoSections, common.ZeroFill, false)
	if buildInfoResult != nil && buildInfoResult.Applied {
		operations = append(operations, buildInfoResult.Message)
		totalCount += buildInfoResult.Count
	} // Strip non-essential sections
	nonEssentialResult := p.StripSectionsByType(common.NonEssentialSections, common.ZeroFill, false)
	if nonEssentialResult != nil && nonEssentialResult.Applied {
		operations = append(operations, nonEssentialResult.Message)
		totalCount += nonEssentialResult.Count
	}

	// Strip symbol tables (safe for most executables)
	symbolResult := p.StripSectionsByType(common.SymbolSections, common.ZeroFill, false)
	if symbolResult != nil && symbolResult.Applied {
		operations = append(operations, symbolResult.Message)
		totalCount += symbolResult.Count
	}

	// Strip exception handling data (risky - requires force flag)
	exceptionResult := p.StripSectionsByType(common.ExceptionSections, common.ZeroFill, force)
	if exceptionResult != nil && exceptionResult.Applied {
		operations = append(operations, fmt.Sprintf("⚠️  %s (risky)", exceptionResult.Message))
		totalCount += exceptionResult.Count
	}
	// Strip Rich Header (compilation metadata)
	richHeaderResult := p.StripRichHeader()
	if richHeaderResult != nil && richHeaderResult.Applied {
		operations = append(operations, richHeaderResult.Message)
		totalCount += richHeaderResult.Count
	}

	// Strip compiler signatures and build metadata (GCC, MinGW, Go, etc.)
	compilerResult := p.StripAllCompilerMetadata()
	if compilerResult != nil && compilerResult.Applied {
		operations = append(operations, compilerResult.Message)
		totalCount += compilerResult.Count
	}
	// Strip version strings and build identifiers (aggressive)
	versionResult := p.StripVersionStrings()
	if versionResult != nil && versionResult.Applied {
		operations = append(operations, versionResult.Message)
		totalCount += versionResult.Count
	}
	// Strip relocation tables (RISKY - may break some executables)
	// Note: This is done last before compaction as it's the most aggressive
	relocationResult := p.StripSectionsByType(common.RelocationSections, common.ZeroFill, force)
	if relocationResult != nil && relocationResult.Applied {
		operations = append(operations, fmt.Sprintf("⚠️  %s (risky)", relocationResult.Message))
		totalCount += relocationResult.Count
	}

	// File compaction (if requested)
	if compact {
		compactResult, err := p.SimpleTruncationPE()
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("simple compaction failed: %v", err))
		}
		if compactResult.Applied {
			operations = append(operations, compactResult.Message)
		}
	}

	if len(operations) == 0 {
		return common.NewSkipped("no stripping operations applied")
	}

	// Calculate final size reduction
	newSize := uint64(len(p.RawData))
	savedBytes := originalSize - newSize
	percentage := float64(savedBytes) * 100.0 / float64(originalSize)

	message := fmt.Sprintf("advanced PE strip completed: %d -> %d bytes (%.1f%% reduction); %s",
		originalSize, newSize, percentage, strings.Join(operations, "; "))

	return common.NewApplied(message, totalCount)
}

// CompactOnlyPEDetailed performs PE compaction without any stripping
func (p *PEFile) CompactOnlyPEDetailed() *common.OperationResult {
	originalSize := uint64(len(p.RawData))

	// Use simple truncation compaction directly
	compactResult, err := p.SimpleTruncationPE()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("simple compaction failed: %v", err))
	}

	if !compactResult.Applied {
		return common.NewSkipped("no compaction was possible")
	}

	// Calculate final size reduction
	newSize := uint64(len(p.RawData))
	savedBytes := originalSize - newSize
	percentage := float64(savedBytes) * 100.0 / float64(originalSize)

	message := fmt.Sprintf("compact-only PE completed: %d -> %d bytes (%.1f%% reduction); %s",
		originalSize, newSize, percentage, compactResult.Message)

	return common.NewApplied(message, compactResult.Count)
}

// SimpleTruncationPE performs safe PE compaction by truncating removable sections
func (p *PEFile) SimpleTruncationPE() (*common.OperationResult, error) {
	if len(p.Sections) == 0 {
		return common.NewSkipped("no sections to process"), nil
	}
	originalSize := uint64(len(p.RawData))

	// Identify removable sections based on DISCARDABLE flag
	removableSections := []int{}
	keptSections := []int{}

	for i, section := range p.Sections {
		// Check if section has DISCARDABLE flag (0x02000000) - but exclude critical sections
		isDiscardable := section.Flags&0x02000000 != 0
		isCriticalDiscardable := section.Name == ".reloc" // Keep relocation table
		if isDiscardable && !isCriticalDiscardable {
			removableSections = append(removableSections, i)
		} else {
			keptSections = append(keptSections, i)
		}
	}

	if len(removableSections) == 0 {
		return common.NewSkipped("no removable sections found"), nil
	}

	// Save names of sections to be removed
	removedSectionNames := make([]string, 0, len(removableSections))
	for _, idx := range removableSections {
		removedSectionNames = append(removedSectionNames, p.Sections[idx].Name)
	}

	// Find the last essential section's end offset
	lastEssentialOffset := uint64(0)
	for _, keptIdx := range keptSections {
		section := p.Sections[keptIdx]
		if section.Size > 0 && section.Offset > 0 {
			sectionEnd := uint64(section.Offset) + uint64(section.Size)
			if sectionEnd > lastEssentialOffset {
				lastEssentialOffset = sectionEnd
			}
		}
	}

	// Align to sector boundary (512 bytes)
	lastEssentialOffset = (lastEssentialOffset + 511) &^ 511

	if lastEssentialOffset >= uint64(len(p.RawData)) {
		return common.NewSkipped("no space to save by truncation"), nil
	}

	// Get PE structure information for header updates
	if len(p.RawData) < 64 {
		return nil, fmt.Errorf("file too small for PE structure")
	}

	peHeaderOffset := uint32(p.RawData[0x3C]) | uint32(p.RawData[0x3D])<<8 |
		uint32(p.RawData[0x3E])<<16 | uint32(p.RawData[0x3F])<<24

	if peHeaderOffset+24 > uint32(len(p.RawData)) {
		return nil, fmt.Errorf("PE header offset out of bounds")
	}

	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	optionalHeaderSize := uint16(p.RawData[coffHeaderOffset+16]) | uint16(p.RawData[coffHeaderOffset+17])<<8
	sectionTableOffset := optionalHeaderOffset + uint32(optionalHeaderSize)
	sectionTableEnd := sectionTableOffset + uint32(len(p.Sections)*40)

	// Make sure we don't truncate the section headers themselves
	minFileSize := uint64(sectionTableEnd)
	if lastEssentialOffset < minFileSize {
		lastEssentialOffset = minFileSize
		// Align to sector boundary (512 bytes)
		lastEssentialOffset = (lastEssentialOffset + 511) &^ 511
	}

	if lastEssentialOffset >= uint64(len(p.RawData)) {
		return common.NewSkipped("no space to save by truncation"), nil
	}
	// For Go executables and other complex PE files, avoid section reorganization
	// that could corrupt string tables or symbol references
	// Instead, just mark removed sections as having zero size and clear their data

	// Check if this looks like a Go executable (has .zdebug_* sections)
	isGoExecutable := false
	for _, name := range removedSectionNames {
		if strings.HasPrefix(name, ".zdebug_") {
			isGoExecutable = true
			break
		}
	}

	// For Go executables, use a very conservative approach
	if isGoExecutable {
		// Calculate space saved by the data that WOULD be removed
		savedBytes := uint64(0)
		for _, idx := range removableSections {
			savedBytes += uint64(p.Sections[idx].Size)
		}
		percentage := float64(savedBytes) * 100.0 / float64(originalSize)

		// Don't actually modify the file structure for Go executables
		// Just report what would be saved
		message := fmt.Sprintf("conservative compaction: would zero %d sections data (%.1f%% logical reduction), sections: %s (file unchanged for compatibility)",
			len(removableSections), percentage, strings.Join(removedSectionNames, ", "))

		return common.NewApplied(message, len(removableSections)), nil
	}

	// First, zero out the data of removable sections (for non-Go executables)
	for _, idx := range removableSections {
		section := p.Sections[idx]
		if section.Offset > 0 && section.Size > 0 {
			start := int(section.Offset)
			end := start + int(section.Size)
			if start < len(p.RawData) && end <= len(p.RawData) {
				// Zero out the section data
				for i := start; i < end; i++ {
					p.RawData[i] = 0
				}
			}
		}
	}

	// Update section count in COFF header to reflect kept sections only
	newSectionCount := uint16(len(keptSections))
	p.RawData[coffHeaderOffset+2] = byte(newSectionCount)
	p.RawData[coffHeaderOffset+3] = byte(newSectionCount >> 8)
	// IMPORTANT: Do NOT zero out COFF symbol table pointers for Go executables
	// as they may have complex string table structures that we could corrupt
	// Only clear if we can verify it's safe to do so

	// Only clear symbol table pointers for non-Go executables
	if !isGoExecutable && coffHeaderOffset+16 <= uint32(len(p.RawData)) {
		// Zero out PointerToSymbolTable (4 bytes at offset +8)
		for i := uint32(8); i < 12; i++ {
			p.RawData[coffHeaderOffset+i] = 0
		}
		// Zero out NumberOfSymbols (4 bytes at offset +12)
		for i := uint32(12); i < 16; i++ {
			p.RawData[coffHeaderOffset+i] = 0
		}
	}

	// Clear section headers for removed sections (but don't reorganize)
	for _, idx := range removableSections {
		offset := sectionTableOffset + uint32(idx*40)
		if offset+40 <= uint32(len(p.RawData)) {
			for j := uint32(0); j < 40; j++ {
				p.RawData[offset+j] = 0
			}
		}
	}
	// For safety with Go executables, skip aggressive truncation
	// Just zero out section data but keep the file structure intact
	if isGoExecutable {
		// Calculate space saved by zeroing BEFORE updating sections
		savedBytes := uint64(0)
		for _, idx := range removableSections {
			savedBytes += uint64(p.Sections[idx].Size)
		}
		percentage := float64(savedBytes) * 100.0 / float64(originalSize)

		// Update internal structure to reflect removed sections
		newSections := make([]Section, 0, len(keptSections))
		for _, keptIdx := range keptSections {
			newSections = append(newSections, p.Sections[keptIdx])
		}
		p.Sections = newSections

		message := fmt.Sprintf("safe compaction: zeroed %d sections data (%.1f%% logical reduction), sections: %s",
			len(removableSections), percentage, strings.Join(removedSectionNames, ", "))

		return common.NewApplied(message, len(removableSections)), nil
	}

	// For non-Go executables, proceed with truncation as before
	// If we have non-contiguous kept sections, we need to skip truncation
	// to avoid corrupting the PE structure
	maxKeptIndex := -1
	for _, keptIdx := range keptSections {
		if keptIdx > maxKeptIndex {
			maxKeptIndex = keptIdx
		}
	}

	if len(keptSections) != maxKeptIndex+1 {
		return common.NewSkipped("non-contiguous sections detected - truncation skipped for safety"), nil
	}

	// NOW truncate the file for non-Go executables
	p.RawData = p.RawData[:lastEssentialOffset]

	// Update internal structure
	newSections := make([]Section, 0, len(keptSections))
	for _, keptIdx := range keptSections {
		newSections = append(newSections, p.Sections[keptIdx])
	}
	p.Sections = newSections
	newSize := uint64(len(p.RawData))
	savedBytes := originalSize - newSize
	percentage := float64(savedBytes) * 100.0 / float64(originalSize)

	message := fmt.Sprintf("simple truncation: %d -> %d bytes (%.1f%% reduction), removed %d sections: %s",
		originalSize, newSize, percentage, len(removableSections), strings.Join(removedSectionNames, ", "))

	return common.NewApplied(message, len(removableSections)), nil
}

// --- Helper Functions ---

// shouldStripForFileType checks if stripping is appropriate for the file type
func (p *PEFile) shouldStripForFileType(sectionType common.SectionType) bool {
	sectionMatchers := common.GetSectionMatchers()
	matcher, exists := sectionMatchers[sectionType]
	if !exists {
		return false
	}

	isDLL := p.isDLL()
	if isDLL {
		return matcher.StripForDLL
	}
	return matcher.StripForEXE
}

// isDLL checks if the PE file is a DLL
func (p *PEFile) isDLL() bool {
	if len(p.RawData) < 64 {
		return false
	}

	peHeaderOffset := uint32(p.RawData[0x3C]) | uint32(p.RawData[0x3D])<<8 |
		uint32(p.RawData[0x3E])<<16 | uint32(p.RawData[0x3F])<<24

	if peHeaderOffset+24 > uint32(len(p.RawData)) {
		return false
	}

	// Check the Characteristics field in the COFF header
	characteristicsOffset := peHeaderOffset + 4 + 18
	if characteristicsOffset+2 > uint32(len(p.RawData)) {
		return false
	}

	characteristics := uint16(p.RawData[characteristicsOffset]) | uint16(p.RawData[characteristicsOffset+1])<<8

	// IMAGE_FILE_DLL = 0x2000
	return characteristics&0x2000 != 0
}

// StripRichHeader removes the Rich Header (hidden Microsoft compilation metadata)
func (p *PEFile) StripRichHeader() *common.OperationResult {
	// Rich Header is located between DOS header and PE header
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	// Search for Rich Header signature "Rich" (0x68636952)
	richSignature := []byte{0x52, 0x69, 0x63, 0x68} // "Rich" in little endian

	// Search in the area between DOS header end and PE header start
	searchStart := int64(dosHeaderSize)
	searchEnd := offsets.ELfanew

	if searchEnd <= searchStart {
		return common.NewSkipped("no space for Rich Header")
	}

	for i := searchStart; i < searchEnd-3; i++ {
		if err := p.validateOffset(i, 4); err != nil {
			continue
		}

		if bytes.Equal(p.RawData[i:i+4], richSignature) {
			// Found Rich Header, now find the start (DanS signature)
			dansSignature := []byte{0x44, 0x61, 0x6E, 0x53} // "DanS"

			// Search backwards for DanS
			for j := i - 4; j >= searchStart; j -= 4 {
				if err := p.validateOffset(j, 4); err != nil {
					continue
				}

				if bytes.Equal(p.RawData[j:j+4], dansSignature) {
					// Found complete Rich Header from j to i+8 (including checksum)
					headerSize := int(i + 8 - j)
					if err := p.validateOffset(j, headerSize); err != nil {
						return common.NewSkipped("Rich Header not accessible")
					}

					// Zero out the entire Rich Header
					for k := 0; k < headerSize; k++ {
						p.RawData[j+int64(k)] = 0x00
					}

					return common.NewApplied(fmt.Sprintf("removed Rich Header (%d bytes)", headerSize), 1)
				}
			}
		}
	}

	return common.NewSkipped("no Rich Header found")
}

// StripAllCompilerMetadata removes compiler version strings, build IDs and signatures
func (p *PEFile) StripAllCompilerMetadata() *common.OperationResult {
	patterns := []*regexp.Regexp{
		// Go Build ID specific (from old StripGoBuildID function)
		regexp.MustCompile(`Go build ID: "[^"]*"`),

		// GCC / MinGW specific
		regexp.MustCompile(`(?i)\bmingw_[a-zA-Z0-9_]*\b`),           // mingw_ symbols
		regexp.MustCompile(`(?i)mingw_[a-zA-Z0-9_]*[.]?`),           // mingw_foo[.] (cattura anche nomi troncati)
		regexp.MustCompile(`(?i)libgcc[a-zA-Z0-9_]*\.[a-zA-Z0-9]+`), // libgcc2.c, libgcc_s_seh-1.dll
		regexp.MustCompile(`(?i)gccmain\.[a-zA-Z0-9]+`),             // gccmain.c, gccmain.o

		// Go versioning and paths
		regexp.MustCompile(`go1\.[0-9]+(\.[0-9]+)?`),
		regexp.MustCompile(`golang\.org/[^\s\x00]+`),
		regexp.MustCompile(`(?i)runtime/[a-zA-Z0-9_/]+\.go`),
		regexp.MustCompile(`(?i)cmd/[^\s\x00]*go[^\s\x00]*`),
		regexp.MustCompile(`(?i)Files/Go/src/[^\s\x00]+`),
		regexp.MustCompile(`(?i)/usr/local/go/[^\s\x00]+`),

		// Build metadata
		regexp.MustCompile(`(?i)\$Id: [^$]*\$`),
		regexp.MustCompile(`(?i)@\(#[^\n\x00]*`),
		regexp.MustCompile(`__DATE__`),
		regexp.MustCompile(`__TIME__`),
		regexp.MustCompile(`__FILE__`),

		// Path stripping (Windows + Unix)
		regexp.MustCompile(`[A-Za-z]:\\[^\s\x00]+`),
		regexp.MustCompile(`/[a-zA-Z0-9/_\-.]+\.(go|c|cpp|h|hpp|rs|py|java|cs|o|obj|dll|exe|so)`),

		// Build environment hints
		regexp.MustCompile(`(?i)compiled\s+by[^\n\x00]*`),
		regexp.MustCompile(`(?i)compiler version[^\n\x00]*`),
		regexp.MustCompile(`(?i)build id[^\n\x00]*`),
	}

	modifications := 0

	for _, section := range p.Sections {
		// Search in all sections, not just specific ones

		data, err := p.ReadBytes(section.Offset, int(section.Size))
		if err != nil || len(data) < 10 {
			continue
		}

		for _, pattern := range patterns {
			matches := pattern.FindAllIndex(data, -1)
			for _, match := range matches {
				// Zero out the compiler signature
				for i := match[0]; i < match[1]; i++ {
					data[i] = 0x00
				}
				modifications++
			}
		}
		if modifications > 0 {
			copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
		}
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("stripped %d compiler metadata entries", modifications), modifications)
	}
	return common.NewSkipped("no compiler metadata found")
}

// StripVersionStrings removes version strings and build identifiers more aggressively
func (p *PEFile) StripVersionStrings() *common.OperationResult {
	patterns := []*regexp.Regexp{
		// Version patterns
		regexp.MustCompile(`v[0-9]+\.[0-9]+\.[0-9]+`),        // Semantic versions
		regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`), // 4-part versions
		regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}`),     // Date formats
		regexp.MustCompile(`[0-9]{2}:[0-9]{2}:[0-9]{2}`),     // Time formats

		// Build identifiers
		regexp.MustCompile(`build-[a-zA-Z0-9-]+`),   // Build IDs
		regexp.MustCompile(`commit-[a-f0-9]{7,40}`), // Git commits
		regexp.MustCompile(`\b[a-f0-9]{32}\b`),      // MD5 hashes
		regexp.MustCompile(`\b[a-f0-9]{40}\b`),      // SHA1 hashes
		regexp.MustCompile(`\b[a-f0-9]{64}\b`),      // SHA256 hashes
	}

	modifications := 0

	for _, section := range p.Sections {
		data, err := p.ReadBytes(section.Offset, int(section.Size))
		if err != nil || len(data) < 10 {
			continue
		}

		for _, pattern := range patterns {
			matches := pattern.FindAllIndex(data, -1)
			for _, match := range matches {
				// Zero out the version string
				for i := match[0]; i < match[1]; i++ {
					data[i] = 0x00
				}
				modifications++
			}
		}

		if modifications > 0 {
			copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
		}
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("stripped %d version strings", modifications), modifications)
	}
	return common.NewSkipped("no version strings found")
}
