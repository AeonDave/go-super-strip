package elfrw

import (
	"fmt"
	"gosstrip/common"
	"regexp"
	"strings"
)

func (e *ELFFile) StripAll(force bool) *common.OperationResult {
	protectedTables := e.snapshotProtectedStringTables()
	defer e.restoreProtectedStringTables(protectedTables)

	originalSize := uint64(len(e.RawData))
	pipeline := common.NewPipeline()
	aggregate := &common.OperationResult{
		Message: "ELF strip",
		Details: []common.OperationDetail{},
	}

	pipeline.AddStep("sections", func() (*common.OperationResult, error) {
		return e.runStripSectionPhase(force), nil
	})
	pipeline.AddStep("headers", func() (*common.OperationResult, error) {
		return e.stripAllHeaders(), nil
	})
	pipeline.AddStep("regex", func() (*common.OperationResult, error) {
		return e.stripAllRegexRules(force), nil
	})

	if err := pipeline.Execute(aggregate); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to strip ELF: %v", err))
	}
	if !aggregate.Applied {
		return common.NewSkipped("no stripping operations applied")
	}

	aggregate.Message = fmt.Sprintf("ELF strip completed: %d bytes processed", originalSize)
	return aggregate
}

func (e *ELFFile) runStripSectionPhase(force bool) *common.OperationResult {
	sectionRules := getSectionStripRule()
	result := common.NewApplied("section stripping", 0)
	isSharedObject := e.IsSharedObject()
	for sectionType, rule := range sectionRules {
		if rule.IsRisky && !force {
			continue
		}
		if (isSharedObject && !rule.StripForSO) || (!isSharedObject && !rule.StripForBIN) {
			continue
		}
		sectionResult := e.stripSectionsByType(sectionType, rule.Fill == RandomFill)
		if sectionResult == nil {
			continue
		}
		if sectionResult.Applied {
			result.Applied = true
			result.Count += sectionResult.Count
			if sectionResult.Message != "" {
				result.AddDetail(sectionResult.Message, sectionResult.Count, rule.IsRisky)
			}
			for _, detail := range sectionResult.Details {
				result.AddDetail(detail.Message, detail.Count, detail.IsRisky)
			}
		}
	}
	if !result.Applied {
		return common.NewSkipped("no sections stripped")
	}
	return result
}

func (e *ELFFile) StripByteRegex(pattern *regexp.Regexp, useRandom bool, force bool) (int, error) {
	if pattern == nil {
		return 0, fmt.Errorf("regex pattern cannot be nil")
	}
	totalMatches := 0
	for _, match := range pattern.FindAllIndex(e.RawData, -1) {
		start, end := match[0], match[1]
		if start < 0 || end > len(e.RawData) || start >= end {
			continue
		}
		if !force && e.matchProtectedStringTableRange(start, end) {
			continue
		}
		if err := e.fillRegion(uint64(start), end-start, useRandom); err != nil {
			return totalMatches, fmt.Errorf("failed to fill pattern at offset %d: %w", start, err)
		}
		totalMatches++
	}
	if totalMatches > 0 {
		e.trimZeroTailBeyond(e.logicalFileEnd())
	}
	return totalMatches, nil
}

func (e *ELFFile) fillRegion(offset uint64, size int, useRandom bool) error {
	return common.FillRegion(e.RawData, int64(offset), size, useRandom)
}

func (e *ELFFile) stripSectionData(sectionIndex int, useRandom bool) error {
	section := &e.Sections[sectionIndex]

	if section.Offset <= 0 || section.Size <= 0 {
		return nil // Already stripped or no content
	}
	if section.Stripped {
		return nil
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
	section.Stripped = true

	return nil
}

func (e *ELFFile) stripSectionsByType(sectionType SectionType, useRandom bool) *common.OperationResult {
	if sectionType == LoaderSections {
		return common.NewSkipped("loader sections are required for execution and cannot be stripped")
	}
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	// Get section rules from strip_types.go
	sectionRules := getSectionStripRule()
	rule, exists := sectionRules[sectionType]
	if !exists {
		return common.NewSkipped(fmt.Sprintf("unknown section type: %v", sectionType))
	}

	// Guard: Do NOT strip relocation sections for dynamically linked binaries (PIE or with interpreter).
	// These sections are required by the dynamic loader (ld.so) at runtime and removing them breaks execution.
	if sectionType == RelocationSections && (e.isDynamic || e.hasInterpreter) {
		return common.NewSkipped("relocation sections are required for dynamically linked binaries; skipping to preserve runtime")
	}

	var strippedSections []string
	for i, section := range e.Sections {
		if common.MatchesPattern(section.Name, rule.ExactNames, rule.PrefixNames) {
			sanitized := strings.ToLower(strings.Trim(strings.TrimSpace(section.Name), "\x00"))
			if sanitized == ".shstrtab" || section.ExecutionCritical {
				continue
			}
			// Only count sections that actually contain data and haven't been stripped yet
			changed := section.Offset > 0 && section.Size > 0
			if err := e.stripSectionData(i, useRandom); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to strip section %s: %v", section.Name, err))
			}
			if changed {
				strippedSections = append(strippedSections, section.Name)
			}
		}
	}

	if len(strippedSections) == 0 {
		return common.NewSkipped(fmt.Sprintf("no %s sections found", rule.Description))
	}

	// Update section headers after modification
	if err := e.updateSectionHeaders(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to update section headers: %v", err))
	}

	message := fmt.Sprintf("stripped %d %s sections (%s)", len(strippedSections), rule.Description, strings.Join(strippedSections, ", "))
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

	// Do NOT zero EI_VERSION (e_ident[6]) or OSABI (e_ident[7]) to preserve validity.
	// Safely clear ELF flags (often toolchain-specific) and non-essential identity bytes.

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

	// Zero out e_ident[EI_ABIVERSION] (ABI version, typically safe)
	if err := e.writeAtOffset(8, uint8(0)); err == nil {
		result.AddDetail("removed ABI version field", 1, false)
		totalCount++
	}

	// Clear e_ident padding (EI_PAD: bytes 9..15)
	if len(e.RawData) >= 16 {
		padZeros := make([]byte, 7)
		if err := e.writeAtOffset(9, padZeros); err == nil {
			result.AddDetail("removed 7 bytes from ELF header padding (EI_PAD)", 1, false)
			totalCount++
		}
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

	modifications, err := e.StripByteRegex(pattern, false, true) // Explicit regex requests override protections
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

	protected := e.snapshotProtectedStringTables()
	defer e.restoreProtectedStringTables(protected)

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

			modifications, err := e.StripByteRegex(pattern, rule.Fill == RandomFill, force)
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

type protectedSectionSnapshot struct {
	offset int
	data   []byte
}

func (e *ELFFile) snapshotProtectedStringTables() []protectedSectionSnapshot {
	var snapshots []protectedSectionSnapshot
	for _, section := range e.Sections {
		if !isProtectedStringTable(section.Name) {
			continue
		}
		if section.Offset < 0 || section.Size <= 0 {
			continue
		}
		start := int(section.Offset)
		end := start + int(section.Size)
		if start < 0 || end > len(e.RawData) {
			continue
		}
		buf := make([]byte, end-start)
		copy(buf, e.RawData[start:end])
		snapshots = append(snapshots, protectedSectionSnapshot{
			offset: start,
			data:   buf,
		})
	}
	return snapshots
}

func (e *ELFFile) restoreProtectedStringTables(snaps []protectedSectionSnapshot) {
	for _, snap := range snaps {
		end := snap.offset + len(snap.data)
		if snap.offset < 0 {
			continue
		}
		if end > len(e.RawData) {
			padding := make([]byte, end-len(e.RawData))
			e.RawData = append(e.RawData, padding...)
		}
		copy(e.RawData[snap.offset:end], snap.data)
	}
}

func (e *ELFFile) matchProtectedStringTableRange(start, end int) bool {
	for _, section := range e.Sections {
		if !isProtectedStringTable(section.Name) {
			continue
		}
		if section.Offset < 0 || section.Size <= 0 {
			continue
		}
		secStart := int(section.Offset)
		secEnd := secStart + int(section.Size)
		if start < secEnd && end > secStart {
			return true
		}
	}
	return false
}

func isProtectedStringTable(name string) bool {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(name), "\x00"))
	return s == ".shstrtab"
}
