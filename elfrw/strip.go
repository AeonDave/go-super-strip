package elfrw

import (
	"crypto/rand"
	"fmt"
	"gosstrip/common"
	"regexp"
	"strings"
)

func (e *ELFFile) StripAll(force bool) *common.OperationResult {
	totalCount := 0
	result := common.NewApplied(fmt.Sprintf("ELF strip completed: %d operations applied", 0), 0)

	sectionRules := getSectionStripRule()
	for sectionType, rule := range sectionRules {
		if rule.IsRisky && !force {
			continue
		}
		isSharedObject := e.IsDynamic()
		if (isSharedObject && !rule.StripForSO) || (!isSharedObject && !rule.StripForBIN) {
			continue
		}
		sectionResult := e.stripSectionsByType(sectionType, rule.Fill == RandomFill)
		if sectionResult != nil && sectionResult.Applied {
			result.AddDetail(sectionResult.Message, sectionResult.Count, rule.IsRisky)
			totalCount += sectionResult.Count
		}
	}

	if headersResult := e.stripAllHeaders(); headersResult != nil && headersResult.Applied {
		for _, detail := range headersResult.Details {
			result.AddDetail(detail.Message, detail.Count, detail.IsRisky)
		}
		totalCount += headersResult.Count
	}

	if regexResult := e.stripAllRegexRules(force); regexResult != nil && regexResult.Applied {
		for _, detail := range regexResult.Details {
			result.AddDetail(detail.Message, detail.Count, detail.IsRisky)
		}
		totalCount += regexResult.Count
	}

	if totalCount == 0 {
		return common.NewSkipped("no stripping operations applied")
	}

	// Update the message with the actual count
	result.Message = fmt.Sprintf("%d operations applied", totalCount)
	result.Count = totalCount

	return result
}

func (e *ELFFile) StripByteRegex(pattern *regexp.Regexp, useRandom bool) (int, error) {
	if pattern == nil {
		return 0, fmt.Errorf("regex pattern cannot be nil")
	}
	totalMatches := 0
	// Helper to process a match range in the raw data
	process := func(offset uint64, length int) {
		if err := e.fillRegion(offset, length, useRandom); err == nil {
			totalMatches++
		}
	}
	if len(e.Sections) == 0 {
		// Apply regex to entire file
		for _, match := range pattern.FindAllIndex(e.RawData, -1) {
			start, end := match[0], match[1]
			if start < 0 || end > len(e.RawData) || start >= end {
				continue
			}
			process(uint64(start), end-start)
		}
	} else {
		// Apply regex within each section
		for _, section := range e.Sections {
			if section.Offset <= 0 || section.Size <= 0 {
				continue
			}
			base := uint64(section.Offset)
			maxLen := int64(len(e.RawData)) - section.Offset
			if maxLen <= 0 {
				continue
			}
			// Extract section data slice
			secData := e.RawData[base : base+uint64(section.Size)]
			for _, match := range pattern.FindAllIndex(secData, -1) {
				start, end := match[0], match[1]
				if start < 0 || end > len(secData) || start >= end {
					continue
				}
				process(base+uint64(start), end-start)
			}
		}
	}
	return totalMatches, nil
}

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
		zeroBytes := make([]byte, size)
		copy(e.RawData[offset:offset+uint64(size)], zeroBytes)
	}
	return nil
}

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

func (e *ELFFile) stripSectionsByType(sectionType SectionType, useRandom bool) *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	// Get section rules from strip_types.go
	sectionRules := getSectionStripRule()
	rule, exists := sectionRules[sectionType]
	if !exists {
		return common.NewSkipped(fmt.Sprintf("unknown section type: %v", sectionType))
	}

	var strippedSections []string
	for i, section := range e.Sections {
		if common.MatchesPattern(section.Name, rule.ExactNames, rule.PrefixNames) {
			if err := e.stripSectionData(i, useRandom); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to strip section %s: %v", section.Name, err))
			}
			strippedSections = append(strippedSections, section.Name)
		}
	}

	if len(strippedSections) == 0 {
		return common.NewSkipped(fmt.Sprintf("no %s sections found", rule.Description))
	}

	// Update section headers after modification
	if err := e.updateSectionHeaders(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to update section headers: %v", err))
	}

	message := fmt.Sprintf("stripped %s sections: %s", rule.Description, strings.Join(strippedSections, ", "))
	result := common.NewApplied(message, len(strippedSections))
	result.SetCategory("SECTIONS")
	return result
}

func (e *ELFFile) getHeaderPositions() (int, int, int) {
	if e.Is64Bit {
		return ELF64_E_SHOFF, ELF64_E_SHNUM, ELF64_E_SHSTRNDX
	}
	return ELF32_E_SHOFF, ELF32_E_SHNUM, ELF32_E_SHSTRNDX
}

func (e *ELFFile) getSectionHeaderOffset(shoffPos int) (uint64, error) {
	// Ensure we have enough data to read the header
	if e.Is64Bit {
		if shoffPos < 0 || shoffPos+8 > len(e.RawData) {
			return 0, fmt.Errorf("invalid section header offset position: %d", shoffPos)
		}
		offset := e.readUint64(shoffPos)
		if offset >= uint64(len(e.RawData)) {
			return 0, fmt.Errorf("section header offset out of range: %d", offset)
		}
		return offset, nil
	}

	if shoffPos < 0 || shoffPos+4 > len(e.RawData) {
		return 0, fmt.Errorf("invalid section header offset position: %d", shoffPos)
	}
	offset := uint64(e.readUint32(shoffPos))
	if offset >= uint64(len(e.RawData)) {
		return 0, fmt.Errorf("section header offset out of range: %d", offset)
	}
	return offset, nil
}

func (e *ELFFile) stripAllHeaders() *common.OperationResult {
	totalCount := 0
	result := common.NewApplied("Header strip completed", 0)
	result.SetCategory("OTHER")

	if headerResult := e.stripELFHeaderFields(); headerResult != nil && headerResult.Applied {
		result.AddDetail(headerResult.Message, headerResult.Count, false)
		totalCount += headerResult.Count
	}

	if timestampResult := e.stripProgramHeaderTimestamps(); timestampResult != nil && timestampResult.Applied {
		result.AddDetail(timestampResult.Message, timestampResult.Count, false)
		totalCount += timestampResult.Count
	}

	if totalCount == 0 {
		return common.NewSkipped("no header stripping operations were applied")
	}

	result.Count = totalCount
	return result
}

func (e *ELFFile) stripELFHeaderFields() *common.OperationResult {
	totalCount := 0
	result := common.NewApplied("stripped ELF header fields", 0)

	// Zero out e_version (not critical for execution)
	versionOffset := 6 // Same position in both 32-bit and 64-bit ELF
	if err := e.writeAtOffset(versionOffset, uint32(0)); err == nil {
		result.AddDetail("removed ELF version field", 1, false)
		totalCount++
	}

	// Zero out e_flags (often contains compiler-specific flags)
	var flagsOffset int
	if e.Is64Bit {
		flagsOffset = ELF64_E_FLAGS
	} else {
		flagsOffset = ELF32_E_FLAGS
	}
	if err := e.writeAtOffset(flagsOffset, uint32(0)); err == nil {
		result.AddDetail("removed ELF flags field", 1, false)
		totalCount++
	}

	// Zero out e_ident[EI_ABIVERSION] (ABI version, often safe to remove)
	if err := e.writeAtOffset(8, byte(0)); err == nil {
		result.AddDetail("removed ABI version field", 1, false)
		totalCount++
	}

	if totalCount == 0 {
		return common.NewSkipped("no header fields were stripped")
	}

	result.Message = fmt.Sprintf("stripped %d ELF header fields", totalCount)
	result.Count = totalCount
	return result
}

func (e *ELFFile) stripProgramHeaderTimestamps() *common.OperationResult {
	totalCount := 0
	result := common.NewApplied("removed program header timestamps", 0)

	// Find PT_NOTE segments that might contain timestamps
	for i, segment := range e.Segments {
		if segment.Type == PT_NOTE && segment.FileSize > 0 {
			// Zero out the data portion of the note segment
			if err := e.fillRegion(segment.Offset, int(segment.FileSize), false); err == nil {
				result.AddDetail(fmt.Sprintf("zeroed PT_NOTE segment %d", i), 1, false)
				totalCount++
			}
		}
	}

	if totalCount == 0 {
		return common.NewSkipped("no program header timestamps found")
	}

	result.Message = fmt.Sprintf("removed timestamps from %d program headers", totalCount)
	result.Count = totalCount
	return result
}

func (e *ELFFile) StripSingleRegexRule(regex string) *common.OperationResult {
	pattern, err := regexp.Compile(regex)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("invalid regex '%s': %v", regex, err))
	}

	modifications, err := e.StripByteRegex(pattern, false) // Use zero fill by default
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("error processing '%s': %v", regex, err))
	}

	message := fmt.Sprintf("stripped %d matches for '%s'", modifications, regex)
	result := common.NewApplied(message, modifications)
	result.SetCategory("PATTERNS")
	return result
}

func (e *ELFFile) stripAllRegexRules(force bool) *common.OperationResult {
	rules := GetRegexStripRules()
	totalModifications := 0
	result := common.NewApplied("Regex pattern stripping", 0)
	result.SetCategory("PATTERNS")

	for _, rule := range rules {
		if rule.IsRisky && !force {
			continue
		}

		for _, patternStr := range rule.Patterns {
			pattern, err := regexp.Compile(patternStr)
			if err != nil {
				// Just log the error and continue
				continue
			}

			modifications, err := e.StripByteRegex(pattern, rule.Fill == RandomFill)
			if err != nil {
				// Just log the error and continue
				continue
			}

			if modifications > 0 {
				msg := fmt.Sprintf("stripped %d matches for '%s' (%s)", modifications, patternStr, rule.Description)
				result.AddDetail(msg, modifications, rule.IsRisky)
				totalModifications += modifications
			}
		}
	}

	if totalModifications > 0 {
		result.Message = fmt.Sprintf("stripped %d regex pattern matches", totalModifications)
		result.Count = totalModifications
		return result
	}
	return common.NewSkipped("no regex-based metadata found")
}
