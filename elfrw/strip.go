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
		for i := uint64(0); i < uint64(size); i++ {
			e.RawData[offset+i] = 0
		}
	}
	return nil
}

func (e *ELFFile) ZeroFill(offset uint64, size int) error {
	return e.fillRegion(offset, size, false)
}

func (e *ELFFile) RandomFill(offset uint64, size int) error {
	return e.fillRegion(offset, size, true)
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

		if common.MatchesPattern(section.Name, exactNames, prefixNames) {
			if err := e.stripSectionData(i, useRandom); err != nil {
				return err
			}
			strippedCount++
		}
	}

	return e.UpdateSectionHeaders()
}

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

func (e *ELFFile) clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos int) error {
	if err := e.writeAtOffset(shoffPos, uint64(0)); err != nil {
		return err
	}
	if err := e.writeAtOffset(shNumPos, uint16(0)); err != nil {
		return err
	}
	return e.writeAtOffset(shStrNdxPos, uint16(0))
}

func (e *ELFFile) getHeaderPositions() (int, int, int) {
	if e.Is64Bit {
		return 40, 60, 62 // e_shoff, e_shnum, e_shstrndx for 64-bit
	}
	return 32, 48, 50 // e_shoff, e_shnum, e_shstrndx for 32-bit
}

func (e *ELFFile) getSectionHeaderOffset(shoffPos int) uint64 {
	if e.Is64Bit {
		return e.readUint64(shoffPos)
	}
	return uint64(e.readUint32(shoffPos))
}

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
	originalSize := uint64(len(e.RawData))
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

	newSize := uint64(len(e.RawData))
	bytesRemoved := originalSize - newSize

	message := fmt.Sprintf("ELF strip completed: %d bytes processed", originalSize)
	if bytesRemoved > 0 {
		message += fmt.Sprintf(" (%d bytes removed)", bytesRemoved)
	}
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
