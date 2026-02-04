package perw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"regexp"
	"strings"
)

func (p *PEFile) StripSectionsByType(sectionType SectionType, fillMode FillMode, force bool) *common.OperationResult {
	sectionMatchers := GetSectionStripRule()
	matcher, exists := sectionMatchers[sectionType]
	if !exists {
		return common.NewSkipped(fmt.Sprintf("unknown section type: %v", sectionType))
	}

	if matcher.IsRisky && !force {
		return common.NewSkipped(fmt.Sprintf("%s skipped (risky operation, enable with -s=force=true)", matcher.Description))
	}

	if !p.shouldStripForFileType(sectionType) {
		return common.NewSkipped("not applicable for this file type")
	}

	strippedCount := 0
	var strippedSections []string
	for idx := range p.Sections {
		section := &p.Sections[idx]
		if !p.sectionMatchesRule(sectionType, section, matcher, force) {
			continue
		}

		if err := p.wipeSectionData(section, fillMode); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to fill section %s: %v", section.Name, err))
		}
		section.Stripped = true
		strippedCount++
		strippedSections = append(strippedSections, section.Name)
	}
	if strippedCount == 0 {
		return common.NewSkipped(fmt.Sprintf("no %s found", matcher.Description))
	}
	if sectionType == SymbolSections && strippedCount > 0 {
		if err := p.fixCOFFHeaderAfterStripping(); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to fix COFF header: %v", err))
		}
	}
	message := fmt.Sprintf("stripped %d %s sections (%s)", strippedCount, matcher.Description, strings.Join(strippedSections, ", "))
	return common.NewApplied(message, strippedCount)
}

func (p *PEFile) StripByPattern(pattern *regexp.Regexp, fillMode FillMode, force bool) (int, error) {
	if pattern == nil {
		return 0, fmt.Errorf("regex pattern cannot be nil")
	}

	totalMatches := 0
	matches, err := common.FindAllRegexMatches(pattern, p.RawData)
	if err != nil {
		return 0, err
	}
	// Build protected ranges if not force mode
	protected := []sectionRange(nil)
	if !force {
		protected = p.buildProtectedRegexRangesForPattern(pattern)
	}
	for _, match := range matches {
		start, end := match[0], match[1]
		if start < 0 || end > len(p.RawData) || start >= end {
			continue
		}
		// Skip matches that overlap protected ranges (unless force)
		if !force && rangesOverlap(protected, start, end) {
			continue
		}
		if err := p.fillRegion(int64(start), end-start, fillMode); err != nil {
			return totalMatches, fmt.Errorf("failed to fill pattern at offset %d: %w", start, err)
		}
		totalMatches++
	}

	if totalMatches > 0 {
		p.trimZeroTailBeyond(p.maxSectionDataEnd())
	}

	return totalMatches, nil
}

func (p *PEFile) StripAll(force bool, fillOverride *bool) *common.OperationResult {
	originalSize := uint64(len(p.RawData))
	pipeline := common.NewPipeline()
	aggregate := &common.OperationResult{
		Message: "PE strip",
		Details: []common.OperationDetail{},
	}

	pipeline.AddStep("sections", func() (*common.OperationResult, error) {
		return p.runStripSectionPhase(force, fillOverride), nil
	})
	pipeline.AddStep("headers", func() (*common.OperationResult, error) {
		return p.StripAllHeaders(force), nil
	})
	pipeline.AddStep("directories", func() (*common.OperationResult, error) {
		return p.StripAllDirs(force), nil
	})
	pipeline.AddStep("regex", func() (*common.OperationResult, error) {
		return p.StripAllRegexRules(force, fillOverride), nil
	})

	if err := pipeline.Execute(aggregate); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to strip PE: %v", err))
	}
	if !aggregate.Applied {
		return common.NewSkipped("no stripping operations applied")
	}

	aggregate.Message = fmt.Sprintf("PE strip completed: %d bytes processed", originalSize)
	return aggregate
}

func (p *PEFile) runStripSectionPhase(force bool, fillOverride *bool) *common.OperationResult {
	sectionRules := GetSectionStripRule()
	result := common.NewApplied("section stripping", 0)
	for sectionType, rule := range sectionRules {
		if rule.IsRisky && !force {
			continue
		}
		if !p.shouldStripForFileType(sectionType) {
			continue
		}
		fill := rule.Fill
		if fillOverride != nil {
			if *fillOverride {
				fill = RandomFill
			} else {
				fill = ZeroFill
			}
		}
		res := p.StripSectionsByType(sectionType, fill, force)
		if res == nil {
			continue
		}
		if res.Applied {
			result.Applied = true
			result.Count += res.Count
			if res.Message != "" {
				result.AddDetail(res.Message, res.Count, rule.IsRisky)
			}
			for _, detail := range res.Details {
				result.AddDetail(detail.Message, detail.Count, detail.IsRisky)
			}
		}
	}
	if !result.Applied {
		return common.NewSkipped("no sections stripped")
	}
	return result
}

func (p *PEFile) StripAllRegexRules(force bool, fillOverride *bool) *common.OperationResult {
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

			fill := rule.Fill
			if fillOverride != nil {
				if *fillOverride {
					fill = RandomFill
				} else {
					fill = ZeroFill
				}
			}
			modifications, err := p.StripByPattern(pattern, fill, force)
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

func (p *PEFile) ApplyRegexPatterns(patterns []string, fillOverride *bool, force bool) *common.OperationResult {
	if len(patterns) == 0 {
		return common.NewSkipped("no regex patterns provided")
	}
	fill := ZeroFill
	if fillOverride != nil && *fillOverride {
		fill = RandomFill
	}
	total := 0
	var warnings []string
	result := common.NewApplied("regex patterns applied", 0)
	result.SetCategory("PATTERNS")
	for _, patternStr := range patterns {
		pattern, err := regexp.Compile(patternStr)
		if err != nil {
			msg := fmt.Sprintf("invalid regex '%s': %v", patternStr, err)
			result.AddDetail(msg, 0, false)
			warnings = append(warnings, msg)
			continue
		}
		modifications, err := p.StripByPattern(pattern, fill, force)
		if err != nil {
			msg := fmt.Sprintf("error processing '%s': %v", patternStr, err)
			result.AddDetail(msg, 0, false)
			warnings = append(warnings, msg)
			continue
		}
		if modifications > 0 {
			result.AddDetail(fmt.Sprintf("stripped %d matches for '%s'", modifications, patternStr), modifications, false)
			total += modifications
		}
	}
	if total == 0 {
		if len(warnings) > 0 {
			return common.NewSkipped(strings.Join(warnings, "; "))
		}
		return common.NewSkipped("no regex matches found")
	}
	result.Count = total
	return result
}

func (p *PEFile) StripAllHeaders(force bool) *common.OperationResult {
	var operations []string
	totalCount := 0

	// Packed loaders sometimes key off or validate PE header fields.
	// Evidence: packed samples can crash when only the COFF timestamp changes.
	if !(p.IsPacked && !force) {
		if result := p.StripPEHeaderTimeDateStamp(); result != nil && result.Applied {
			operations = append(operations, result.Message)
			totalCount += result.Count
		}
	}

	if result := p.StripRichHeader(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := p.StripHeader(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if totalCount == 0 {
		return common.NewSkipped("no header stripping operations were applied")
	}

	message := fmt.Sprintf("Header strip completed:\n%s", p.formatStripOperations(operations))
	return common.NewApplied(message, totalCount)
}

func (p *PEFile) StripAllDirs(force bool) *common.OperationResult {
	var operations []string
	totalCount := 0

	if result := p.StripDebugDirectory(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if force {
		if result := p.StripImportDirectoryMetadata(); result != nil && result.Applied {
			operations = append(operations, result.Message)
			totalCount += result.Count
		}
	}

	if result := p.StripResourceDirectory(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := p.StripLoadConfigDirectory(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if totalCount == 0 {
		return common.NewSkipped("no dirs stripping operations were applied")
	}

	message := fmt.Sprintf("Debug/Resource strip completed:\n%s", p.formatStripOperations(operations))
	return common.NewApplied(message, totalCount)
}

func (p *PEFile) StripHeader() *common.OperationResult {
	dosReservedStart, dosReservedSize := int64(0x1C), PE_ELFANEW_OFFSET-0x1C
	if err := p.validateOffset(dosReservedStart, dosReservedSize); err != nil {
		return common.NewSkipped("DOS header reserved fields not accessible")
	}
	if err := p.fillRegion(dosReservedStart, dosReservedSize, ZeroFill); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to strip DOS header reserved fields: %v", err))
	}
	return common.NewApplied(fmt.Sprintf("removed %d bytes from DOS header reserved fields", dosReservedSize), 1)
}

func (p *PEFile) StripRichHeader() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}
	richSignature := []byte{0x52, 0x69, 0x63, 0x68} // "Rich" in little endian
	searchStart := int64(PE_DOS_HEADER_SIZE)
	searchEnd := offsets.ELfanew

	if searchEnd <= searchStart {
		return common.NewSkipped("no space for Rich Header")
	}

	for i := searchStart; i < searchEnd-3; i++ {
		if err := p.validateOffset(i, PE_SIGNATURE_SIZE); err != nil {
			continue
		}

		if bytes.Equal(p.RawData[i:i+PE_SIGNATURE_SIZE], richSignature) {
			dansSignature := []byte{0x44, 0x61, 0x6E, 0x53} // "DanS"
			for j := i - PE_SIGNATURE_SIZE; j >= searchStart; j -= PE_SIGNATURE_SIZE {
				if err := p.validateOffset(j, PE_SIGNATURE_SIZE); err != nil {
					continue
				}
				if bytes.Equal(p.RawData[j:j+PE_SIGNATURE_SIZE], dansSignature) {
					headerSize := int(i + 8 - j)
					if err := p.validateOffset(j, headerSize); err != nil {
						return common.NewSkipped("Rich Header not accessible")
					}
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

func (p *PEFile) StripPEHeaderTimeDateStamp() *common.OperationResult {
	if len(p.RawData) < PE_DOS_HEADER_SIZE {
		return common.NewSkipped("file too small for PE structure")
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	coffHeaderOffset := peHeaderOffset + PE_SIGNATURE_SIZE
	timeDateStampOffset := coffHeaderOffset + PE_TIMESTAMP_OFFSET
	if err := p.validateOffset(timeDateStampOffset, 4); err != nil {
		return common.NewSkipped("TimeDateStamp field not accessible")
	}
	for i := 0; i < 4; i++ {
		p.RawData[timeDateStampOffset+int64(i)] = 0
	}
	return common.NewApplied("removed PE header TimeDateStamp", 1)
}

func (p *PEFile) StripSecondaryTimestamps() *common.OperationResult {
	timestampPattern := regexp.MustCompile(`19\d{2}|20\d{2}`)
	targetSections := map[string]bool{".rsrc": true, ".data": true, ".rdata": true}

	totalMatches := 0
	var strippedSections []string

	for _, section := range p.Sections {
		if !targetSections[section.Name] {
			continue
		}
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}
		sectionData, err := p.ReadBytes(section.Offset, int(section.Size))
		if err != nil {
			continue
		}
		matches := timestampPattern.FindAllIndex(sectionData, -1)
		if len(matches) == 0 {
			continue
		}

		sectionModified := false
		for _, match := range matches {
			start := match[0]
			end := match[1]
			if err := p.fillRegion(section.Offset+int64(start), end-start, ZeroFill); err == nil {
				totalMatches++
				sectionModified = true
			}
		}

		if sectionModified {
			strippedSections = append(strippedSections, section.Name)
		}
	}

	if totalMatches == 0 {
		return common.NewSkipped("no secondary timestamps found in data sections")
	}

	message := fmt.Sprintf("stripped %d secondary timestamps from sections: %s", totalMatches, strings.Join(strippedSections, ", "))
	return common.NewApplied(message, totalMatches)
}

func (p *PEFile) StripDebugDirectory() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped("failed to calculate offsets for debug directory")
	}
	debugDirEntryOffset := offsets.OptionalHeader + directoryOffsets.debug[p.Is64Bit]
	if err := p.validateOffset(debugDirEntryOffset, 8); err != nil {
		return common.NewSkipped("debug directory entry not accessible")
	}
	rva := binary.LittleEndian.Uint32(p.RawData[debugDirEntryOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[debugDirEntryOffset+4:])
	if rva == 0 && size == 0 {
		return common.NewSkipped("no debug directory found")
	}
	payloadsWiped := 0
	tableWiped := false
	if rva != 0 && size > 0 {
		if debugDirPhys, err := p.rvaToPhysical(uint64(rva)); err == nil {
			dirStart := int(debugDirPhys)
			if dirStart >= 0 && dirStart < len(p.RawData) {
				maxSize := int(size)
				if dirStart+maxSize > len(p.RawData) {
					maxSize = len(p.RawData) - dirStart
				}
				const entrySize = 28
				zeroEntry := make([]byte, entrySize)
				dirEnd := dirStart + maxSize
				for offset := dirStart; offset+entrySize <= dirEnd; offset += entrySize {
					entry := p.RawData[offset : offset+entrySize]
					if bytes.Equal(entry, zeroEntry) {
						break
					}
					sizeOfData := binary.LittleEndian.Uint32(entry[16:20])
					ptrToRaw := binary.LittleEndian.Uint32(entry[24:28])
					if sizeOfData > 0 && ptrToRaw > 0 {
						payloadStart := int(ptrToRaw)
						if payloadStart < len(p.RawData) {
							payloadEnd := payloadStart + int(sizeOfData)
							if payloadEnd > len(p.RawData) {
								payloadEnd = len(p.RawData)
							}
							if payloadEnd > payloadStart {
								_ = p.fillRegion(int64(payloadStart), payloadEnd-payloadStart, ZeroFill)
								payloadsWiped++
							}
						}
					}
				}
				if maxSize > 0 {
					_ = p.fillRegion(int64(dirStart), maxSize, ZeroFill)
					tableWiped = true
				}
			}
		}
	}
	if err := p.fillRegion(debugDirEntryOffset, 8, ZeroFill); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to strip debug directory entry: %v", err))
	}
	message := "removed debug directory entry from PE header"
	if tableWiped {
		message = "removed debug directory entry from PE header; wiped debug directory data"
		if payloadsWiped > 0 {
			message = fmt.Sprintf("%s and %d payload(s)", message, payloadsWiped)
		}
	}
	return common.NewApplied(message, 1)
}

func (p *PEFile) StripResourceDirectory() *common.OperationResult {
	section := p.findSectionByName(".rsrc")
	if section == nil {
		return common.NewSkipped("no resource section (.rsrc) found")
	}
	if section.Size < 16 {
		return common.NewSkipped("resource section is too small to contain a directory header")
	}
	resourceHeaderOffset := section.Offset
	if err := p.validateOffset(resourceHeaderOffset, 16); err != nil {
		return common.NewSkipped("resource directory header not accessible")
	}
	modifications := 0
	if err := p.fillRegion(resourceHeaderOffset+4, 4, ZeroFill); err == nil {
		modifications++
	}
	if err := p.fillRegion(resourceHeaderOffset+8, 4, ZeroFill); err == nil {
		modifications++
	}
	if modifications == 0 {
		return common.NewSkipped("could not strip any fields from resource directory header")
	}
	return common.NewApplied("removed timestamp and version from resource directory header", modifications)
}

func (p *PEFile) StripLoadConfigDirectory() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}
	dirOffset := offsets.OptionalHeader + directoryOffsets.loadConfig[p.Is64Bit]
	if err := p.validateOffset(dirOffset, 8); err != nil {
		return common.NewSkipped("load config directory offset validation failed")
	}
	rva := binary.LittleEndian.Uint32(p.RawData[dirOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[dirOffset+4:])
	if rva == 0 || size < 12 {
		return common.NewSkipped("no valid load configuration directory found")
	}
	loadConfigPhysical, err := p.rvaToPhysical(uint64(rva))
	if err != nil {
		return common.NewSkipped("failed to convert load config RVA to physical")
	}
	if err := p.validateOffset(int64(loadConfigPhysical), 12); err != nil {
		return common.NewSkipped("load configuration structure not accessible")
	}
	modifications := 0
	if err := p.fillRegion(int64(loadConfigPhysical+4), 4, ZeroFill); err == nil {
		modifications++
	}
	if err := p.fillRegion(int64(loadConfigPhysical+8), 4, ZeroFill); err == nil {
		modifications++
	}
	if modifications > 0 {
		return common.NewApplied("removed timestamp and version from load config directory", modifications)
	}
	return common.NewSkipped("no load config fields could be stripped")
}

func (p *PEFile) StripImportDirectoryMetadata() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}
	importDirOffset := offsets.OptionalHeader + directoryOffsets.importTable[p.Is64Bit]
	if err := p.validateOffset(importDirOffset, 8); err != nil {
		return common.NewSkipped("import directory entry not accessible")
	}
	rva := binary.LittleEndian.Uint32(p.RawData[importDirOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[importDirOffset+4:])
	if rva == 0 || size < 20 {
		return common.NewSkipped("no import directory found")
	}
	importPhys, err := p.rvaToPhysical(uint64(rva))
	if err != nil || int(importPhys) >= len(p.RawData) {
		return common.NewSkipped("failed to map import directory RVA")
	}
	maxSize := int(size)
	if int(importPhys)+maxSize > len(p.RawData) {
		maxSize = len(p.RawData) - int(importPhys)
	}
	if maxSize < 20 {
		return common.NewSkipped("import directory entry not accessible")
	}

	const descriptorSize = 20
	zeroDesc := make([]byte, descriptorSize)
	modifications := 0
	entries := 0
	for offset := int(importPhys); offset+descriptorSize <= int(importPhys)+maxSize; offset += descriptorSize {
		desc := p.RawData[offset : offset+descriptorSize]
		if bytes.Equal(desc, zeroDesc) {
			break
		}
		entries++
		if binary.LittleEndian.Uint32(desc[4:8]) != 0 {
			for i := 0; i < 4; i++ {
				desc[4+i] = 0
			}
			modifications++
		}
		if binary.LittleEndian.Uint32(desc[8:12]) != 0 {
			for i := 0; i < 4; i++ {
				desc[8+i] = 0
			}
			modifications++
		}
	}
	if modifications == 0 {
		return common.NewSkipped("no import descriptor metadata found")
	}
	message := fmt.Sprintf("cleared import descriptor metadata in %d entries", entries)
	return common.NewApplied(message, modifications)
}

func (p *PEFile) StripSingleRegexRule(regex string) *common.OperationResult {
	pattern, err := regexp.Compile(regex)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("invalid regex '%s': %v", regex, err))
	}
	modifications, err := p.StripByPattern(pattern, ZeroFill, true)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("error processing '%s': %v", regex, err))
	}

	return common.NewApplied(fmt.Sprintf("stripped %d matches for '%s'", modifications, regex), modifications)
}

func (p *PEFile) fillRegion(offset int64, size int, mode FillMode) error {
	switch mode {
	case ZeroFill, RandomFill:
		return common.FillRegion(p.RawData, offset, size, mode == RandomFill)
	default:
		return fmt.Errorf("unknown fill mode: %v", mode)
	}
}

func (p *PEFile) shouldStripForFileType(sectionType SectionType) bool {
	matcher, ok := GetSectionStripRule()[sectionType]
	if !ok {
		return false
	}
	if p.isDLL() {
		return matcher.StripForDLL
	}
	return matcher.StripForEXE
}

func (p *PEFile) isDLL() bool {
	if len(p.RawData) < PE_DOS_HEADER_SIZE {
		return false
	}
	peHeaderOffset := binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4])
	if peHeaderOffset+26 > uint32(len(p.RawData)) {
		return false
	}
	characteristics := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+22 : peHeaderOffset+24])
	return characteristics&0x2000 != 0
}

func (p *PEFile) formatStripOperations(operations []string) string {
	if len(operations) == 0 {
		return "No operations performed"
	}

	var result strings.Builder
	grouped := map[string][]string{
		"section": {},
		"regex":   {},
		"other":   {},
	}

	for _, op := range operations {
		switch {
		case strings.Contains(op, "sections ("):
			grouped["section"] = append(grouped["section"], op)
		case strings.Contains(op, "matches for"):
			grouped["regex"] = append(grouped["regex"], op)
		default:
			grouped["other"] = append(grouped["other"], op)
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

func (p *PEFile) maxSectionDataEnd() int64 {
	var maxEnd int64
	for _, section := range p.Sections {
		if section.Offset < 0 || section.Size <= 0 {
			continue
		}
		end := section.Offset + section.Size
		if end > maxEnd {
			maxEnd = end
		}
	}
	return maxEnd
}

func (p *PEFile) trimZeroTailBeyond(limit int64) {
	if limit <= 0 || limit >= int64(len(p.RawData)) {
		return
	}
	for _, b := range p.RawData[limit:] {
		if b != 0 {
			return
		}
	}
	p.RawData = p.RawData[:limit]
	p.FileSize = int64(len(p.RawData))
	p.HasOverlay = false
	p.OverlayOffset = 0
	p.OverlaySize = 0
}

type sectionRange struct {
	start int
	end   int
}

func (p *PEFile) buildProtectedRegexRanges() []sectionRange {
	ranges := make([]sectionRange, 0, 8)

	// Protect a small window around the entrypoint stub (executed loader code).
	if epRVA, err := p.GetEntryPoint(); err == nil && epRVA != 0 {
		if phys, err := p.rvaToPhysical(uint64(epRVA)); err == nil {
			start := int(phys)
			end := start + 0x1000 // one page is enough to cover the stub in typical packed layouts
			if start < 0 {
				start = 0
			}
			if end > len(p.RawData) {
				end = len(p.RawData)
			}
			if start < end {
				ranges = append(ranges, sectionRange{start: start, end: end})
			}
		}
	}

	// Protect Import Directory/IAT region - touched by loader and easy to corrupt.
	offsets, err := p.calculateOffsets()
	if err == nil {
		importDirOffset := offsets.OptionalHeader + directoryOffsets.importTable[p.Is64Bit]
		if importDirOffset+8 <= int64(len(p.RawData)) {
			rva := binary.LittleEndian.Uint32(p.RawData[importDirOffset:])
			size := binary.LittleEndian.Uint32(p.RawData[importDirOffset+4:])
			if rva != 0 && size > 0 {
				if phys, err := p.rvaToPhysical(uint64(rva)); err == nil {
					start := int(phys)
					end := start + int(size)
					if start >= 0 && end <= len(p.RawData) && start < end {
						ranges = append(ranges, sectionRange{start: start, end: end})
					}
				}
			}
		}
	}

	// Generic packed-binary protection: packed payload sections often contain compressed/encrypted
	// data. Regex patterns can match by chance inside that data and corrupt the stream.
	// Protect the whole packed payload section(s) so regex stripping only affects safer areas.
	if p.IsPacked {
		const largeSection = 0x20000
		for _, section := range p.Sections {
			if section.Offset <= 0 || section.Size <= 0 {
				continue
			}
			isRWX := section.Flags&IMAGE_SCN_MEM_EXECUTE != 0 && section.Flags&IMAGE_SCN_MEM_WRITE != 0
			isHighEntropy := section.Entropy >= 7.0
			isLikelyPayload := isHighEntropy || (isRWX && section.Size >= largeSection)
			if !isLikelyPayload {
				continue
			}
			start := int(section.Offset)
			end := start + int(section.Size)
			if start < 0 || start >= len(p.RawData) {
				continue
			}
			if end > len(p.RawData) {
				end = len(p.RawData)
			}
			if start < end {
				ranges = append(ranges, sectionRange{start: start, end: end})
			}
		}
	}
	return ranges
}

func (p *PEFile) buildProtectedRegexRangesForPattern(pattern *regexp.Regexp) []sectionRange {
	// Start with the default protected ranges.
	ranges := p.buildProtectedRegexRanges()
	// For UPX header patterns, allow matches inside packed payload to restore previous behavior.
	// We still protect entrypoint and import ranges.
	if isUPXHeaderPattern(pattern) {
		filtered := make([]sectionRange, 0, len(ranges))
		for _, r := range ranges {
			if !p.isPackedPayloadRange(r) {
				filtered = append(filtered, r)
			}
		}
		return filtered
	}
	return ranges
}

func (p *PEFile) isPackedPayloadRange(r sectionRange) bool {
	if !p.IsPacked {
		return false
	}
	const largeSection = 0x20000
	for _, section := range p.Sections {
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}
		isRWX := section.Flags&IMAGE_SCN_MEM_EXECUTE != 0 && section.Flags&IMAGE_SCN_MEM_WRITE != 0
		isHighEntropy := section.Entropy >= 7.0
		isLikelyPayload := isHighEntropy || (isRWX && section.Size >= largeSection)
		if !isLikelyPayload {
			continue
		}
		start := int(section.Offset)
		end := start + int(section.Size)
		if start < 0 || start >= len(p.RawData) {
			continue
		}
		if end > len(p.RawData) {
			end = len(p.RawData)
		}
		if r.start >= start && r.end <= end {
			return true
		}
	}
	return false
}

func isUPXHeaderPattern(pattern *regexp.Regexp) bool {
	if pattern == nil {
		return false
	}
	p := pattern.String()
	if !strings.Contains(p, "UPX!") {
		return false
	}
	// Version + UPX header patterns.
	if strings.Contains(p, "[0-9]\\.[0-9]{2}") {
		return true
	}
	if strings.Contains(p, "\\x00") || strings.Contains(p, "\\s+") {
		return true
	}
	return false
}

func rangesOverlap(ranges []sectionRange, start, end int) bool {
	for _, r := range ranges {
		if start < r.end && end > r.start {
			return true
		}
	}
	return false
}

func (p *PEFile) rvaToPhysical(rva uint64) (uint64, error) {
	for _, section := range p.Sections {
		if rva >= uint64(section.VirtualAddress) &&
			rva < uint64(section.VirtualAddress+section.VirtualSize) {
			offset := rva - uint64(section.VirtualAddress)
			return uint64(section.Offset) + offset, nil
		}
	}
	return 0, fmt.Errorf("RVA %x not found in any section", rva)
}

func (p *PEFile) physicalToRVA(offset uint32) (uint32, error) {
	for _, section := range p.Sections {
		start := uint32(section.Offset)
		size := uint32(section.Size)
		if size == 0 {
			continue
		}
		if offset >= start && offset < start+size {
			return section.VirtualAddress + (offset - start), nil
		}
	}
	if offset < p.sizeOfHeaders {
		return offset, nil
	}
	return 0, fmt.Errorf("file offset 0x%x not mapped to RVA", offset)
}

func (p *PEFile) fixCOFFHeaderAfterStripping() error {
	if len(p.RawData) < PE_DOS_HEADER_SIZE {
		return fmt.Errorf("file too small for PE structure")
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	if peHeaderOffset < 0 || peHeaderOffset+PE_FILE_HEADER_SIZE+PE_SIGNATURE_SIZE >= int64(len(p.RawData)) {
		return fmt.Errorf("invalid PE header")
	}

	coffHeaderOffset := peHeaderOffset + PE_SIGNATURE_SIZE
	if coffHeaderOffset+16 > int64(len(p.RawData)) {
		return fmt.Errorf("invalid COFF header")
	}
	symbolTableOffset := binary.LittleEndian.Uint32(p.RawData[coffHeaderOffset+8 : coffHeaderOffset+12])
	numberOfSymbols := binary.LittleEndian.Uint32(p.RawData[coffHeaderOffset+12 : coffHeaderOffset+16])
	if symbolTableOffset == 0 && numberOfSymbols == 0 {
		return nil
	}
	stringTableCorrupted := false
	if symbolTableOffset > 0 && numberOfSymbols > 0 {
		stringTableOffset := int64(symbolTableOffset) + int64(numberOfSymbols)*18
		if stringTableOffset+4 > int64(len(p.RawData)) {
			stringTableCorrupted = true
		} else {
			stringTableSize := binary.LittleEndian.Uint32(p.RawData[stringTableOffset : stringTableOffset+4])
			if stringTableOffset+int64(stringTableSize) > int64(len(p.RawData)) {
				stringTableCorrupted = true
			}
		}
	}
	if stringTableCorrupted {
		if err := WriteAtOffset(p.RawData, coffHeaderOffset+8, uint32(0)); err != nil {
			return err
		}
		if err := WriteAtOffset(p.RawData, coffHeaderOffset+12, uint32(0)); err != nil {
			return err
		}
	}
	return nil
}
