package elfrw

import (
	"crypto/rand"
	"fmt"
	"gosstrip/common"
	"regexp"
	"strings"
)

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

func (e *ELFFile) StripSectionsByType(sectionType SectionType, useRandom bool) *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	// Get section rules from strip_types.go
	sectionRules := GetSectionStripRule()
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
	if err := e.UpdateSectionHeaders(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to update section headers: %v", err))
	}

	message := fmt.Sprintf("stripped %s sections: %s", rule.Description, strings.Join(strippedSections, ", "))
	return common.NewApplied(message, len(strippedSections))
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

func (e *ELFFile) getHeaderPositions() (int, int, int) {
	if e.Is64Bit {
		return 40, 60, 62 // e_shoff, e_shnum, e_shstrndx for 64-bit
	}
	return 32, 48, 50
}

func (e *ELFFile) getSectionHeaderOffset(shoffPos int) uint64 {
	if e.Is64Bit {
		return e.readUint64(shoffPos)
	}
	return uint64(e.readUint32(shoffPos))
}

func (e *ELFFile) StripAllHeaders() *common.OperationResult {
	var operations []string
	totalCount := 0

	// Strip ELF header fields
	if result := e.StripELFHeaderFields(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	// Strip program header timestamps
	if result := e.StripProgramHeaderTimestamps(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if totalCount == 0 {
		return common.NewSkipped("no header stripping operations were applied")
	}

	message := fmt.Sprintf("Header strip completed: %s", strings.Join(operations, ", "))
	return common.NewApplied(message, totalCount)
}

func (e *ELFFile) StripELFHeaderFields() *common.OperationResult {
	var operations []string
	totalCount := 0

	// Zero out e_version (not critical for execution)
	versionOffset := 6 // Same position in both 32-bit and 64-bit ELF
	if err := e.writeAtOffset(versionOffset, uint32(0)); err == nil {
		operations = append(operations, "removed ELF version field")
		totalCount++
	}

	// Zero out e_flags (often contains compiler-specific flags)
	var flagsOffset int
	if e.Is64Bit {
		flagsOffset = 48
	} else {
		flagsOffset = 36
	}
	if err := e.writeAtOffset(flagsOffset, uint32(0)); err == nil {
		operations = append(operations, "removed ELF flags field")
		totalCount++
	}

	// Zero out e_ident[EI_ABIVERSION] (ABI version, often safe to remove)
	if err := e.writeAtOffset(8, byte(0)); err == nil {
		operations = append(operations, "removed ABI version field")
		totalCount++
	}

	if totalCount == 0 {
		return common.NewSkipped("no header fields were stripped")
	}

	return common.NewApplied(fmt.Sprintf("stripped %d ELF header fields", totalCount), totalCount)
}

func (e *ELFFile) StripProgramHeaderTimestamps() *common.OperationResult {
	var operations []string
	totalCount := 0

	// Find PT_NOTE segments that might contain timestamps
	for i, segment := range e.Segments {
		if segment.Type == PT_NOTE && segment.FileSize > 0 {
			// Zero out the data portion of the note segment
			if err := e.fillRegion(segment.Offset, int(segment.FileSize), false); err == nil {
				operations = append(operations, fmt.Sprintf("zeroed PT_NOTE segment %d", i))
				totalCount++
			}
		}
	}

	if totalCount == 0 {
		return common.NewSkipped("no program header timestamps found")
	}

	return common.NewApplied(fmt.Sprintf("removed timestamps from %d program headers", totalCount), totalCount)
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

	return common.NewApplied(fmt.Sprintf("stripped %d matches for '%s'", modifications, regex), modifications)
}

func (e *ELFFile) StripAllRegexRules(force bool) *common.OperationResult {
	rules := GetRegexStripRules()
	totalModifications := 0
	var messages []string

	for _, rule := range rules {
		if rule.IsRisky && !force {
			continue
		}

		for _, patternStr := range rule.Patterns {
			pattern, err := regexp.Compile(patternStr)
			if err != nil {
				messages = append(messages, fmt.Sprintf("invalid regex '%s': %v", patternStr, err))
				continue
			}

			modifications, err := e.StripByteRegex(pattern, rule.Fill == RandomFill)
			if err != nil {
				messages = append(messages, fmt.Sprintf("error processing '%s': %v", patternStr, err))
				continue
			}

			if modifications > 0 {
				msg := fmt.Sprintf("stripped %d matches for '%s' (%s)", modifications, patternStr, rule.Description)
				messages = append(messages, msg)
				totalModifications += modifications
			}
		}
	}

	if totalModifications > 0 {
		return common.NewApplied(strings.Join(messages, "; "), totalModifications)
	}
	return common.NewSkipped("no regex-based metadata found")
}

func (e *ELFFile) StripAll(force bool) *common.OperationResult {
	var operations []string
	totalCount := 0

	// 1. Use section rules from GetSectionStripRule()
	sectionRules := GetSectionStripRule()
	for sectionType, rule := range sectionRules {
		if rule.IsRisky && !force {
			continue
		}

		// Apply appropriate security checks based on file type
		isSharedObject := e.IsSharedObject()
		if (isSharedObject && !rule.StripForSO) || (!isSharedObject && !rule.StripForBIN) {
			continue
		}

		// Strip sections by type
		result := e.StripSectionsByType(sectionType, rule.Fill == RandomFill)
		if result != nil && result.Applied {
			message := result.Message
			if rule.IsRisky {
				message = fmt.Sprintf("⚠️  %s (risky)", message)
			}
			operations = append(operations, message)
			totalCount += result.Count
		}
	}

	// 2. Strip all headers
	if headersResult := e.StripAllHeaders(); headersResult != nil && headersResult.Applied {
		operations = append(operations, headersResult.Message)
		totalCount += headersResult.Count
	}

	//3. Strip regex patterns
	if regexResult := e.StripAllRegexRules(force); regexResult != nil && regexResult.Applied {
		operations = append(operations, regexResult.Message)
		totalCount += regexResult.Count
	}

	if totalCount == 0 {
		return common.NewSkipped("no stripping operations applied")
	}
	// Report number of operations applied
	message := fmt.Sprintf("ELF strip completed: %d operations applied", totalCount)
	message += "\n" + formatStripOperations(operations)
	return common.NewApplied(message, totalCount)
}

func formatStripOperations(operations []string) string {
	if len(operations) == 0 {
		return "No operations performed"
	}

	var result strings.Builder
	grouped := map[string][]string{
		"section": {},
		"regex":   {},
		"other":   {},
	}

	// Use maps to track unique operations
	uniqueOps := map[string]map[string]bool{
		"section": make(map[string]bool),
		"regex":   make(map[string]bool),
		"other":   make(map[string]bool),
	}

	for _, op := range operations {
		switch {
		case strings.Contains(op, "sections ("):
			if !uniqueOps["section"][op] {
				uniqueOps["section"][op] = true
				grouped["section"] = append(grouped["section"], op)
			}
		case strings.Contains(op, "matches for"):
			if !uniqueOps["regex"][op] {
				uniqueOps["regex"][op] = true
				grouped["regex"] = append(grouped["regex"], op)
			}
		default:
			if !uniqueOps["other"][op] {
				uniqueOps["other"][op] = true
				grouped["other"] = append(grouped["other"], op)
			}
		}
	}

	if len(grouped["section"]) > 0 {
		result.WriteString("📦 SECTIONS STRIPPED:\n")
		for _, op := range grouped["section"] {
			prefix := "   ✓ "
			if strings.HasPrefix(op, "⚠️") {
				prefix = "   "
			}
			result.WriteString(prefix + op + "\n")
		}
	}
	if len(grouped["regex"]) > 0 {
		result.WriteString("🔍 REGEX PATTERNS STRIPPED:\n")
		for _, op := range grouped["regex"] {
			for _, msg := range strings.Split(op, "; ") {
				msg = strings.TrimSpace(msg)
				if msg != "" {
					result.WriteString("   ✓ " + msg + "\n")
				}
			}
		}
	}
	if len(grouped["other"]) > 0 {
		result.WriteString("🛠️ OTHER OPERATIONS:\n")
		for _, op := range grouped["other"] {
			prefix := "   ✓ "
			if strings.HasPrefix(op, "⚠️") {
				prefix = "   "
			}
			result.WriteString(prefix + op + "\n")
		}
	}

	return strings.TrimSuffix(result.String(), "\n")
}
