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
func (p *PEFile) StripRelocationTable(useRandomFill bool, force bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.RelocationSections, fillMode, force) // Pass force parameter through
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
func (p *PEFile) StripExceptionHandlingData(useRandomFill bool, force bool) *common.OperationResult {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}
	return p.StripSectionsByType(common.ExceptionSections, fillMode, force) // Pass force parameter through
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
func (p *PEFile) StripAllMetadata(useRandomFill bool, force bool) error {
	fillMode := common.ZeroFill
	if useRandomFill {
		fillMode = common.RandomFill
	}

	// List of section types to strip (safe operations only)
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
	if force {
		result := p.StripSectionsByType(common.RelocationSections, fillMode, force)
		if result != nil && result.Applied {
			log.Printf("WARNING: Stripped relocation sections (risky): %s", result.Message)
		}
	}

	return nil
}

// --- Main Strip and Compact Functions ---

// CompactAndStripPE performs aggressive PE stripping with actual file size reduction

// AdvancedStripPEDetailed performs comprehensive PE stripping (no compaction)
func (p *PEFile) AdvancedStripPEDetailed(force bool) *common.OperationResult {
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
	}

	// Strip non-essential sections
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
	// Strip all regex-based metadata (compiler, version, build info, etc.)
	regexResult := p.StripAllRegexRules(force)
	if regexResult != nil && regexResult.Applied {
		operations = append(operations, regexResult.Message)
		totalCount += regexResult.Count
	}

	// Strip relocation tables (RISKY - may break some executables)
	relocationResult := p.StripSectionsByType(common.RelocationSections, common.ZeroFill, force)
	if relocationResult != nil && relocationResult.Applied {
		operations = append(operations, fmt.Sprintf("⚠️  %s (risky)", relocationResult.Message))
		totalCount += relocationResult.Count
	}

	if len(operations) == 0 {
		return common.NewSkipped("no stripping operations applied")
	}

	// Build professional output message
	message := fmt.Sprintf("PE strip completed: %d bytes processed\n%s",
		originalSize, p.formatStripOperations(operations))

	return common.NewApplied(message, totalCount)
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

// StripAllRegexRules applica tutte le regole regex centralizzate su tutte le sezioni
func (p *PEFile) StripAllRegexRules(force bool) *common.OperationResult {
	rules := common.GetRegexStripRules()
	totalModifications := 0
	messages := []string{}

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
			modifications := 0
			for _, section := range p.Sections {
				data, err := p.ReadBytes(section.Offset, int(section.Size))
				if err != nil || len(data) < 1 {
					continue
				}
				matches := pattern.FindAllIndex(data, -1)
				for _, match := range matches {
					for i := match[0]; i < match[1]; i++ {
						data[i] = 0x00
					}
					modifications++
				}
				if modifications > 0 {
					copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
				}
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

// formatStripOperations formats the stripping operations into a professional output
func (p *PEFile) formatStripOperations(operations []string) string {
	if len(operations) == 0 {
		return "No operations performed"
	}

	var result strings.Builder

	// Group operations by type for better readability
	sectionOps := []string{}
	regexOps := []string{}
	otherOps := []string{}

	for _, op := range operations {
		if strings.Contains(op, "sections (") {
			sectionOps = append(sectionOps, op)
		} else if strings.Contains(op, "matches for") {
			regexOps = append(regexOps, op)
		} else {
			otherOps = append(otherOps, op)
		}
	}

	// Format section operations
	if len(sectionOps) > 0 {
		result.WriteString("📦 SECTIONS STRIPPED:\n")
		for _, op := range sectionOps {
			if strings.HasPrefix(op, "⚠️") {
				result.WriteString(fmt.Sprintf("   %s\n", op))
			} else {
				result.WriteString(fmt.Sprintf("   ✓ %s\n", op))
			}
		}
	}

	// Format regex operations (if any)
	if len(regexOps) > 0 {
		result.WriteString("🔍 REGEX PATTERNS STRIPPED:\n")
		for _, op := range regexOps {
			// Split the concatenated regex messages and format each one
			regexMessages := strings.Split(op, "; ")
			for _, regexMsg := range regexMessages {
				if strings.TrimSpace(regexMsg) != "" {
					result.WriteString(fmt.Sprintf("   ✓ %s\n", strings.TrimSpace(regexMsg)))
				}
			}
		}
	}

	// Format other operations
	if len(otherOps) > 0 {
		result.WriteString("🛠️  OTHER OPERATIONS:\n")
		for _, op := range otherOps {
			if strings.HasPrefix(op, "⚠️") {
				result.WriteString(fmt.Sprintf("   %s\n", op))
			} else {
				result.WriteString(fmt.Sprintf("   ✓ %s\n", op))
			}
		}
	}

	return strings.TrimSuffix(result.String(), "\n")
}
