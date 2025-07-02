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
		return common.NewSkipped(fmt.Sprintf("%s skipped (risky operation, use -f to force)", matcher.Description))
	}

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
	if sectionType == SymbolSections && strippedCount > 0 {
		if err := p.fixCOFFHeaderAfterStripping(); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to fix COFF header: %v", err))
		}
	}
	message := fmt.Sprintf("stripped %d %s sections (%s)", strippedCount, matcher.Description, strings.Join(strippedSections, ", "))
	return common.NewApplied(message, strippedCount)
}

func (p *PEFile) StripByPattern(pattern *regexp.Regexp, fillMode FillMode) (int, error) {
	if pattern == nil {
		return 0, fmt.Errorf("regex pattern cannot be nil")
	}

	totalMatches := 0
	for _, section := range p.Sections {
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}

		sectionStart := section.Offset
		sectionEnd := section.Offset + section.Size

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

func (p *PEFile) StripAll(force bool) *common.OperationResult {
	originalSize := uint64(len(p.RawData))
	var operations []string
	totalCount := 0
	sectionRules := GetSectionStripRule()
	for sectionType, rule := range sectionRules {
		if rule.IsRisky && !force {
			continue
		}
		if !p.shouldStripForFileType(sectionType) {
			continue
		}
		result := p.StripSectionsByType(sectionType, rule.Fill, force)
		if result != nil && result.Applied {
			message := result.Message
			if rule.IsRisky {
				message = fmt.Sprintf("⚠️  %s (risky)", message)
			}
			operations = append(operations, message)
			totalCount += result.Count
		}
	}
	// StripAll StripAllHeaders
	if timeDateStampResult := p.StripAllHeaders(); timeDateStampResult != nil && timeDateStampResult.Applied {
		operations = append(operations, timeDateStampResult.Message)
		totalCount += timeDateStampResult.Count
	}
	// StripAll Debug Directory
	if debugDirResult := p.StripAllDirs(); debugDirResult != nil && debugDirResult.Applied {
		operations = append(operations, debugDirResult.Message)
		totalCount += debugDirResult.Count
	}
	// StripAll regex-based patterns
	if regexResult := p.StripAllRegexRules(force); regexResult != nil && regexResult.Applied {
		operations = append(operations, regexResult.Message)
		totalCount += regexResult.Count
	}
	if len(operations) == 0 {
		return common.NewSkipped("no stripping operations applied")
	}
	message := fmt.Sprintf("PE strip completed: %d bytes processed\n%s",
		originalSize, p.formatStripOperations(operations))

	return common.NewApplied(message, totalCount)
}

func (p *PEFile) StripAllRegexRules(force bool) *common.OperationResult {
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

			modifications, err := p.StripByPattern(pattern, rule.Fill)
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

func (p *PEFile) StripAllHeaders() *common.OperationResult {
	var operations []string
	totalCount := 0

	if result := p.StripPEHeaderTimeDateStamp(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
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

func (p *PEFile) StripAllDirs() *common.OperationResult {
	var operations []string
	totalCount := 0

	if result := p.StripDebugDirectory(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := p.StripResourceDirectory(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := p.StripLoadConfigDirectory(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := p.StripTlsDirectory(); result != nil && result.Applied {
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
	dosReservedStart, dosReservedSize := int64(0x1C), 0x3C-0x1C
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
			dansSignature := []byte{0x44, 0x61, 0x6E, 0x53} // "DanS"
			for j := i - 4; j >= searchStart; j -= 4 {
				if err := p.validateOffset(j, 4); err != nil {
					continue
				}
				if bytes.Equal(p.RawData[j:j+4], dansSignature) {
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
	if len(p.RawData) < 64 {
		return common.NewSkipped("file too small for PE structure")
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	coffHeaderOffset := peHeaderOffset + 4
	timeDateStampOffset := coffHeaderOffset + 4
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
	if err := p.fillRegion(debugDirEntryOffset, 8, ZeroFill); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to strip debug directory entry: %v", err))
	}
	return common.NewApplied("removed debug directory entry from PE header", 1)
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

func (p *PEFile) StripTlsDirectory() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}
	dirOffset := offsets.OptionalHeader + directoryOffsets.tls[p.Is64Bit]
	if err := p.validateOffset(dirOffset, 8); err != nil {
		return common.NewSkipped("TLS directory offset validation failed")
	}
	rva := binary.LittleEndian.Uint32(p.RawData[dirOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[dirOffset+4:])
	if rva == 0 || size < 0x18 { // TLS directory minima: 0x18 (32bit), 0x28 (64bit)
		return common.NewSkipped("no valid TLS directory found")
	}
	tlsPhysical, err := p.rvaToPhysical(uint64(rva))
	if err != nil {
		return common.NewSkipped("failed to convert TLS RVA to physical")
	}
	// TimeDateStamp: offset 0x10 (4 byte), MajorVersion: 0x14 (2 byte), MinorVersion: 0x16 (2 byte)
	if err := p.validateOffset(int64(tlsPhysical+0x10), 8); err != nil {
		return common.NewSkipped("TLS directory fields not accessible")
	}
	modifications := 0
	if err := p.fillRegion(int64(tlsPhysical+0x10), 4, ZeroFill); err == nil {
		modifications++
	}
	if err := p.fillRegion(int64(tlsPhysical+0x14), 4, ZeroFill); err == nil {
		modifications++
	}
	if modifications > 0 {
		return common.NewApplied("removed timestamp and version from TLS directory", modifications)
	}
	return common.NewSkipped("no TLS directory fields could be stripped")
}

func (p *PEFile) StripSingleRegexRule(regex string) *common.OperationResult {
	pattern, err := regexp.Compile(regex)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("invalid regex '%s': %v", regex, err))
	}
	modifications, err := p.StripByPattern(pattern, ZeroFill)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("error processing '%s': %v", regex, err))
	}

	return common.NewApplied(fmt.Sprintf("stripped %d matches for '%s'", modifications, regex), modifications)
}

func (p *PEFile) fillRegion(offset int64, size int, mode FillMode) error {
	if offset < 0 || size <= 0 || offset+int64(size) > int64(len(p.RawData)) {
		return fmt.Errorf("invalid region: offset %d, size %d, total %d", offset, size, len(p.RawData))
	}
	region := p.RawData[offset : offset+int64(size)]
	switch mode {
	case ZeroFill:
		common.ZeroFillData(region)
	case RandomFill:
		if err := common.RandomFillData(region); err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
	default:
		return fmt.Errorf("unknown fill mode: %v", mode)
	}
	return nil
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
	if len(p.RawData) < 64 {
		return false
	}
	peHeaderOffset := binary.LittleEndian.Uint32(p.RawData[0x3C:0x40])
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

func (p *PEFile) fixCOFFHeaderAfterStripping() error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small for PE structure")
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	if peHeaderOffset < 0 || peHeaderOffset+24 >= int64(len(p.RawData)) {
		return fmt.Errorf("invalid PE header")
	}

	coffHeaderOffset := peHeaderOffset + 4
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
