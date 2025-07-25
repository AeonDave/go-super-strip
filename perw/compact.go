package perw

import (
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"sort"
	"strings"
)

func (p *PEFile) Compact(force bool) *common.OperationResult {
	result, err := p.sectionRemoval(force)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to compact: %v", err))
	}
	return result
}

func (p *PEFile) identifyCriticalSections() map[int]struct{} {
	critical := make(map[int]struct{})
	for i, sec := range p.Sections {
		name := strings.ToLower(strings.Trim(sec.Name, "\x00"))
		switch name {
		case ".text", ".code",
			".data", ".rdata",
			".idata", ".edata",
			".pdata", ".xdata",
			".tls",
			".reloc":
			critical[i] = struct{}{}
		}
		if strings.Contains(name, "go.") ||
			strings.Contains(name, "runtime") ||
			strings.Contains(name, "eh_frame") ||
			strings.Contains(name, ".ctors") ||
			strings.Contains(name, ".dtors") {
			critical[i] = struct{}{}
		}
	}
	return critical
}

func (p *PEFile) identifyStripSections(force bool) (removable, keepable []int) {
	rules := GetSectionStripRule()
	protected := p.sectionsReferencedByDataDirectories()
	criticalSections := p.identifyCriticalSections()

	for i, section := range p.Sections {
		if _, ok := protected[i]; ok {
			keepable = append(keepable, i)
			continue
		}
		if _, ok := criticalSections[i]; ok {
			keepable = append(keepable, i)
			continue
		}

		isRemovable := false
		if p.isCorruptedSection(section) {
			isRemovable = true
		} else if force && p.isNullOrZeroSection(section) {
			isRemovable = true
		} else {
			for sectionType, rule := range rules {
				if rule.IsRisky && !force {
					continue
				}

				if !p.shouldStripForFileType(sectionType) {
					continue
				}

				if common.MatchesPattern(section.Name, rule.ExactNames, rule.PrefixNames) {
					isRemovable = true
					break
				}
			}
		}

		if isRemovable {
			removable = append(removable, i)
		} else {
			keepable = append(keepable, i)
		}
	}
	return
}

func (p *PEFile) isCorruptedSection(section Section) bool {
	sectionName := strings.Trim(section.Name, "\x00")
	corruptedPatterns := []string{
		"<coff_ref_",
		"\\",
		"/",
	}
	for _, pattern := range corruptedPatterns {
		if strings.HasPrefix(sectionName, pattern) {
			return true
		}
	}
	if p.hasInvalidCharacters(sectionName) {
		return true
	}
	if p.hasSuspiciousSize(section) {
		return true
	}
	if p.hasInvalidOffsets(section) {
		return true
	}
	return false
}

func (p *PEFile) hasInvalidCharacters(name string) bool {
	if len(name) == 0 {
		return false
	}

	for _, char := range name {
		if char < 32 && char != 0 {
			return true
		}
		if char > 126 && char < 160 {
			return true
		}
		if strings.ContainsRune("\"<>|?*", char) {
			return true
		}
	}

	if strings.HasPrefix(name, "\\") && len(name) > 1 {
		remainder := name[1:]
		if strings.Trim(remainder, "0123456789") == "" {
			return true
		}
	}

	return false
}

func (p *PEFile) hasSuspiciousSize(section Section) bool {
	if section.VirtualSize > 0 && section.Size > 0 {
		ratio := float64(section.VirtualSize) / float64(section.Size)
		if ratio > 1000 || ratio < 0.001 {
			return true
		}
	}
	if section.Offset > 0 && section.Size > 0 {
		if section.Offset+section.Size > int64(len(p.RawData)) {
			return true
		}
	}
	if section.VirtualSize > 1024*1024*1024 {
		return true
	}

	return false
}

func (p *PEFile) hasInvalidOffsets(section Section) bool {
	if section.Offset < 0 {
		return true
	}
	if section.VirtualAddress > 0 {
		if section.VirtualAddress%0x1000 != 0 && section.VirtualAddress%0x200 != 0 {
			return true
		}
	}
	if section.Offset > int64(len(p.RawData)) {
		return true
	}

	return false
}

func (p *PEFile) sectionsReferencedByDataDirectories() map[int]struct{} {
	protected := make(map[int]struct{}, PE_DATA_DIRECTORY_COUNT)
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	coffHeaderOffset := peHeaderOffset + PE_SIGNATURE_SIZE
	optionalHeaderOffset := coffHeaderOffset + PE_FILE_HEADER_SIZE
	var dataDirBase int64
	if p.Is64Bit {
		dataDirBase = optionalHeaderOffset + PE64_DATA_DIRECTORIES
	} else {
		dataDirBase = optionalHeaderOffset + PE32_DATA_DIRECTORIES
	}
	for i := 0; i < PE_DATA_DIRECTORY_COUNT; i++ {
		entryOff := dataDirBase + int64(i*IMAGE_SIZEOF_DATA_DIRECTORY)
		if int(entryOff+IMAGE_SIZEOF_DATA_DIRECTORY) > len(p.RawData) {
			break
		}
		rva := binary.LittleEndian.Uint32(p.RawData[entryOff:])
		size := binary.LittleEndian.Uint32(p.RawData[entryOff+4:])
		if rva == 0 || size == 0 {
			continue
		}
		for idx, s := range p.Sections {
			if s.VirtualAddress <= rva && rva < s.VirtualAddress+s.VirtualSize {
				protected[idx] = struct{}{}
				break
			}
		}
	}
	return protected
}

func (p *PEFile) sectionRemoval(force bool) (*common.OperationResult, error) {
	if len(p.Sections) == 0 {
		return common.NewSkipped("no sections to process"), nil
	}

	originalSize := uint64(len(p.RawData))
	removableSectionIndices, _ := p.identifyStripSections(force)

	if len(removableSectionIndices) == 0 {
		return common.NewSkipped("no removable sections found"), nil
	}

	removedRVAs := make(map[uint32]bool)
	removedNames := make([]string, 0, len(removableSectionIndices))
	for _, idx := range removableSectionIndices {
		if idx >= 0 && idx < len(p.Sections) {
			removedRVAs[p.Sections[idx].VirtualAddress] = true
			removedNames = append(removedNames, p.Sections[idx].Name)
		}
	}
	fileAlignment, err := p.extractFileAlignment()
	if err != nil {
		return nil, fmt.Errorf("failed to extract file alignment: %w", err)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(removableSectionIndices)))
	totalRemovedSize := int64(0)
	for _, sectionIdx := range removableSectionIndices {
		if err := p.removeSingleSection(sectionIdx, &totalRemovedSize, fileAlignment); err != nil {
			return nil, fmt.Errorf("failed to remove section %d: %w", sectionIdx, err)
		}
	}
	if err := p.updateNumberOfSections(len(p.Sections) - len(removableSectionIndices)); err != nil {
		return nil, fmt.Errorf("failed to update NumberOfSections: %w", err)
	}
	newSections := p.buildNewSectionsWithCorrectVirtualSize(removableSectionIndices, removedRVAs)
	if err := p.updateSectionTableWithNewSections(newSections); err != nil {
		return nil, fmt.Errorf("failed to update section table: %w", err)
	}
	if err := p.clearDataDirectoriesForRemovedRVAs(removedRVAs); err != nil {
		return nil, fmt.Errorf("failed to clear data directories: %w", err)
	}
	p.Sections = newSections
	newSize := uint64(len(p.RawData))
	percentage := float64(originalSize-newSize) * 100.0 / float64(originalSize)
	message := fmt.Sprintf("rimozione sezioni: %d -> %d byte (riduzione del %.1f%%), rimosse %d sezioni: %s",
		originalSize, newSize, percentage, len(removableSectionIndices), strings.Join(removedNames, ", "))
	return common.NewApplied(message, len(removableSectionIndices)), nil
}

func (p *PEFile) extractFileAlignment() (uint32, error) {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	coffHeaderOffset := peHeaderOffset + PE_SIGNATURE_SIZE
	optionalHeaderOffset := coffHeaderOffset + PE_FILE_HEADER_SIZE
	fileAlignmentOffset := optionalHeaderOffset + PE32_FILE_ALIGN // Same for PE32 and PE64

	if fileAlignmentOffset+4 > int64(len(p.RawData)) {
		return PE_FILE_ALIGNMENT_MIN, nil // Default fallback
	}

	fileAlignment := binary.LittleEndian.Uint32(p.RawData[fileAlignmentOffset:])
	if fileAlignment == 0 || fileAlignment < PE_FILE_ALIGNMENT_MIN {
		fileAlignment = PE_FILE_ALIGNMENT_MIN // Default minimum
	}

	return fileAlignment, nil
}

func (p *PEFile) removeSingleSection(sectionIdx int, totalRemovedSize *int64, fileAlignment uint32) error {
	if sectionIdx < 0 || sectionIdx >= len(p.Sections) {
		return fmt.Errorf("invalid section index: %d", sectionIdx)
	}

	sectionToRemove := p.Sections[sectionIdx]
	if sectionToRemove.Offset > 0 && sectionToRemove.Size > 0 {
		alignedSize := common.AlignUp64(sectionToRemove.Size, int64(fileAlignment))
		start := int(sectionToRemove.Offset)
		end := int(sectionToRemove.Offset + alignedSize)

		if end > len(p.RawData) {
			end = len(p.RawData)
		}

		newRawData := make([]byte, len(p.RawData)-(end-start))
		copy(newRawData[:start], p.RawData[:start])
		copy(newRawData[start:], p.RawData[end:])
		p.RawData = newRawData
		removedSize := int64(end - start)
		*totalRemovedSize += removedSize
		for i := range p.Sections {
			if i != sectionIdx && p.Sections[i].Offset > sectionToRemove.Offset {
				p.Sections[i].Offset -= removedSize
			}
		}
	}

	return nil
}

func (p *PEFile) buildNewSectionsWithCorrectVirtualSize(removedIndices []int, removedRVAs map[uint32]bool) []Section {
	removedMap := make(map[int]bool)
	for _, idx := range removedIndices {
		removedMap[idx] = true
	}
	newSections := make([]Section, 0, len(p.Sections)-len(removedIndices))
	for i, section := range p.Sections {
		if !removedMap[i] {
			newSections = append(newSections, section)
		}
	}
	for i := 0; i < len(newSections)-1; i++ {
		currentSection := &newSections[i]
		nextSection := &newSections[i+1]
		hasRemovedSectionBetween := false
		for rva := range removedRVAs {
			if rva > currentSection.VirtualAddress && rva < nextSection.VirtualAddress {
				hasRemovedSectionBetween = true
				break
			}
		}
		if hasRemovedSectionBetween {
			currentSection.VirtualSize = nextSection.VirtualAddress - currentSection.VirtualAddress
		}
	}

	return newSections
}

func (p *PEFile) updateSectionTableWithNewSections(newSections []Section) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+PE_SIGNATURE_SIZE+PE_OPTSIZE_OFFSET:])
	sectionTableOffset := peHeaderOffset + PE_SIGNATURE_SIZE + PE_FILE_HEADER_SIZE + int64(optionalHeaderSize)
	sectionTableSize := len(p.Sections) * PE_SECTION_HEADER_SIZE
	if sectionTableOffset+int64(sectionTableSize) > int64(len(p.RawData)) {
		sectionTableSize = len(p.RawData) - int(sectionTableOffset)
	}
	for i := 0; i < sectionTableSize; i++ {
		p.RawData[sectionTableOffset+int64(i)] = 0
	}
	for i, section := range newSections {
		hdrOff := sectionTableOffset + int64(i*PE_SECTION_HEADER_SIZE)
		if hdrOff+PE_SECTION_HEADER_SIZE > int64(len(p.RawData)) {
			break
		}
		copy(p.RawData[hdrOff:hdrOff+PE_SECTION_NAME_SIZE], section.Name)
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+PE_SECTION_VIRTUAL_SIZE:], section.VirtualSize)
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+PE_SECTION_VIRTUAL_ADDR:], section.VirtualAddress)
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+PE_SECTION_RAW_SIZE:], uint32(section.Size))
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+PE_SECTION_RAW_OFFSET:], uint32(section.Offset))
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+PE_SECTION_RELOC_OFFSET:], section.PointerToRelocations)
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+PE_SECTION_LINENUMBER_OFFSET:], section.PointerToLineNumbers)
		binary.LittleEndian.PutUint16(p.RawData[hdrOff+PE_SECTION_RELOC_COUNT:], section.NumberOfRelocations)
		binary.LittleEndian.PutUint16(p.RawData[hdrOff+PE_SECTION_LINENUMBER_COUNT:], section.NumberOfLineNumbers)
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+PE_SECTION_CHARACTERISTICS:], section.Flags)
	}
	return nil
}

func (p *PEFile) clearDataDirectoriesForRemovedRVAs(removedRVAs map[uint32]bool) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	coffHeaderOffset := peHeaderOffset + PE_SIGNATURE_SIZE
	optionalHeaderOffset := coffHeaderOffset + PE_FILE_HEADER_SIZE

	var dataDirectoryOffset int64
	if p.Is64Bit {
		dataDirectoryOffset = optionalHeaderOffset + PE64_DATA_DIRECTORIES
	} else {
		dataDirectoryOffset = optionalHeaderOffset + PE32_DATA_DIRECTORIES
	}
	for i := 0; i < PE_DATA_DIRECTORY_COUNT; i++ {
		entryOffset := dataDirectoryOffset + int64(i*IMAGE_SIZEOF_DATA_DIRECTORY)
		if entryOffset+IMAGE_SIZEOF_DATA_DIRECTORY > int64(len(p.RawData)) {
			break
		}
		rva := binary.LittleEndian.Uint32(p.RawData[entryOffset:])
		if rva == 0 {
			continue
		}
		if removedRVAs[rva] {
			binary.LittleEndian.PutUint32(p.RawData[entryOffset:], 0)
			binary.LittleEndian.PutUint32(p.RawData[entryOffset+4:], 0)
		}
	}
	return nil
}

func (p *PEFile) updateNumberOfSections(newCount int) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	coffHeaderOffset := peHeaderOffset + PE_SIGNATURE_SIZE
	numberOfSectionsOffset := coffHeaderOffset + 2 // This is part of the COFF File Header, not a separate constant usually
	if numberOfSectionsOffset+2 > int64(len(p.RawData)) {
		return fmt.Errorf("NumberOfSections offset out of bounds")
	}
	binary.LittleEndian.PutUint16(p.RawData[numberOfSectionsOffset:], uint16(newCount))
	return nil
}

func (p *PEFile) isNullOrZeroSection(section Section) bool {
	if section.Size <= 0 || section.Offset <= 0 || section.Offset >= int64(len(p.RawData)) {
		return false
	}
	endOffset := section.Offset + section.Size
	if endOffset > int64(len(p.RawData)) {
		endOffset = int64(len(p.RawData))
	}
	if endOffset-section.Offset < 16 {
		return false
	}
	if section.Entropy == 0.0 {
		section.Entropy = common.CalculateEntropy(p.RawData[section.Offset:endOffset])
	}
	return section.Entropy < 0.1
}
