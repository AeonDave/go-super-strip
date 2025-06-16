package perw

import (
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
func (p *PEFile) StripSectionsByType(sectionType common.SectionType, fillMode common.FillMode) *common.OperationResult {
	sectionMatchers := common.GetSectionMatchers()
	matcher, exists := sectionMatchers[sectionType]
	if !exists {
		return common.NewSkipped(fmt.Sprintf("unknown section type: %v", sectionType))
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
	return p.StripSectionsByType(common.DebugSections, fillMode)
}

// StripSymbolTables strips symbol table sections
func (p *PEFile) StripSymbolTables(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.SymbolSections, fillMode)
}

// StripRelocationTable strips relocation table sections
func (p *PEFile) StripRelocationTable(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.RelocationSections, fillMode)
}

// StripNonEssentialSections strips non-essential metadata sections
func (p *PEFile) StripNonEssentialSections(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.NonEssentialSections, fillMode)
}

// StripExceptionHandlingData strips exception handling data
func (p *PEFile) StripExceptionHandlingData(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.ExceptionSections, fillMode)
}

// StripBuildInfoSections strips build information sections
func (p *PEFile) StripBuildInfoSections(useRandomFill bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.BuildInfoSections, fillMode)
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
		result := p.StripSectionsByType(sectionType, fillMode)
		if result != nil && result.Applied {
			log.Printf("Stripped: %s", result.Message)
		}
	}

	// Handle relocation sections separately (risky operation)
	result := p.StripSectionsByType(common.RelocationSections, fillMode)
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
	debugResult := p.StripSectionsByType(common.DebugSections, common.ZeroFill)
	if debugResult != nil && debugResult.Applied {
		operations = append(operations, debugResult.Message)
		totalCount += debugResult.Count
	}

	// Strip build info and non-essential sections if requested
	if removeNonEssential {
		buildInfoResult := p.StripSectionsByType(common.BuildInfoSections, common.ZeroFill)
		if buildInfoResult != nil && buildInfoResult.Applied {
			operations = append(operations, buildInfoResult.Message)
			totalCount += buildInfoResult.Count
		}

		nonEssentialResult := p.StripSectionsByType(common.NonEssentialSections, common.ZeroFill)
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
func (p *PEFile) AdvancedStripPEDetailed(compact bool) *common.OperationResult {
	originalSize := uint64(len(p.RawData))
	operations := []string{}
	totalCount := 0

	// Strip debug sections (always safe)
	debugResult := p.StripSectionsByType(common.DebugSections, common.ZeroFill)
	if debugResult != nil && debugResult.Applied {
		operations = append(operations, debugResult.Message)
		totalCount += debugResult.Count
	}

	// Strip build info and metadata
	buildInfoResult := p.StripSectionsByType(common.BuildInfoSections, common.ZeroFill)
	if buildInfoResult != nil && buildInfoResult.Applied {
		operations = append(operations, buildInfoResult.Message)
		totalCount += buildInfoResult.Count
	}

	// Strip non-essential sections
	nonEssentialResult := p.StripSectionsByType(common.NonEssentialSections, common.ZeroFill)
	if nonEssentialResult != nil && nonEssentialResult.Applied {
		operations = append(operations, nonEssentialResult.Message)
		totalCount += nonEssentialResult.Count
	}

	// Strip Rich Header (compilation metadata)
	richHeaderResult := p.ObfuscateRichHeader()
	if richHeaderResult != nil && richHeaderResult.Applied {
		operations = append(operations, richHeaderResult.Message)
		totalCount += richHeaderResult.Count
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
	log.Printf("Starting SimpleTruncationPE - File size: %d bytes, sections: %d", originalSize, len(p.Sections))

	// Identify removable sections based on DISCARDABLE flag
	removableSections := []int{}
	keptSections := []int{}

	for i, section := range p.Sections {
		// Check if section has DISCARDABLE flag (0x02000000) - but exclude critical sections
		isDiscardable := section.Flags&0x02000000 != 0
		isCriticalDiscardable := section.Name == ".reloc" // Keep relocation table

		if isDiscardable && !isCriticalDiscardable {
			log.Printf("Section %d (%s) is removable (DISCARDABLE flag 0x%x)", i, section.Name, section.Flags)
			removableSections = append(removableSections, i)
		} else {
			keptSections = append(keptSections, i)
			if isCriticalDiscardable {
				log.Printf("Section %d (%s) is essential (critical discardable, flags 0x%x)", i, section.Name, section.Flags)
			} else {
				log.Printf("Section %d (%s) is essential (flags 0x%x)", i, section.Name, section.Flags)
			}
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

	// Update section count in COFF header BEFORE truncating
	newSectionCount := uint16(len(keptSections))
	p.RawData[coffHeaderOffset+2] = byte(newSectionCount)
	p.RawData[coffHeaderOffset+3] = byte(newSectionCount >> 8)
	log.Printf("Updated section count: %d -> %d", len(p.Sections), newSectionCount)

	// For simplicity and safety, only clear the section headers of sections that come
	// AFTER all kept sections. This avoids complex reorganization which could corrupt
	// the PE structure.

	// Find the highest index among kept sections
	maxKeptIndex := -1
	for _, keptIdx := range keptSections {
		if keptIdx > maxKeptIndex {
			maxKeptIndex = keptIdx
		}
	}

	// Only clear section headers for sections beyond the highest kept index
	clearedCount := 0
	for i := maxKeptIndex + 1; i < len(p.Sections); i++ {
		offset := sectionTableOffset + uint32(i*40)
		if offset+40 <= uint32(len(p.RawData)) {
			for j := uint32(0); j < 40; j++ {
				p.RawData[offset+j] = 0
			}
			clearedCount++
		}
	}

	// If we have non-contiguous kept sections, we need to skip this optimization
	// to avoid corrupting the PE structure
	if len(keptSections) != maxKeptIndex+1 {
		log.Printf("WARNING: Non-contiguous section removal detected - skipping truncation for safety")
		return common.NewSkipped("non-contiguous sections detected - truncation skipped for safety"), nil
	}

	log.Printf("Cleared %d section headers after index %d", clearedCount, maxKeptIndex)

	// NOW truncate the file
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

	log.Printf("SimpleTruncationPE completed - Size: %d -> %d bytes (saved %d bytes, %.1f%% reduction)",
		originalSize, newSize, savedBytes, percentage)

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
