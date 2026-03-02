package perw

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"math"
	"sort"
	"strings"
)

type virtualRange struct {
	start uint32
	end   uint32
}

func (p *PEFile) Compact(force bool, keepResources bool) *common.OperationResult {
	origTimestamp, tsOffset := p.readTimeDateStamp()

	pipeline := common.NewPipeline()
	result := &common.OperationResult{
		Message: "PE compaction",
		Details: []common.OperationDetail{},
	}

	pipeline.AddStep("section removal", func() (*common.OperationResult, error) {
		return p.sectionRemoval(force, keepResources)
	})
	pipeline.AddStep("restore timestamp", func() (*common.OperationResult, error) {
		p.restoreTimeDateStamp(origTimestamp, tsOffset)
		return nil, nil
	})
	if force {
		pipeline.AddStep("scrub headers", func() (*common.OperationResult, error) {
			p.scrubSectionHeaderNames()
			return nil, nil
		})
	}

	if err := pipeline.Execute(result); err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to compact: %v", err))
	}
	if !result.Applied {
		return common.NewSkipped("no compactable sections found")
	}
	result.Message = "PE compaction completed"
	return result
}

func (p *PEFile) identifyCriticalSections(force bool, keepResources bool) map[int]struct{} {
	requiredNames := []string{
		".text", ".code",
		".data", ".rdata",
	}
	protectedNames := []string{
		".idata", ".edata",
		".pdata", ".xdata",
		".tls",
		".reloc",
	}
	critical := make(map[int]struct{})
	for i, sec := range p.Sections {
		name := strings.ToLower(strings.Trim(sec.Name, "\x00"))
		for _, req := range requiredNames {
			if name == req {
				critical[i] = struct{}{}
				goto nextSection
			}
		}
		if !force {
			for _, opt := range protectedNames {
				if name == opt {
					critical[i] = struct{}{}
					goto nextSection
				}
			}
		}
		if keepResources && strings.HasPrefix(name, ".rsrc") {
			critical[i] = struct{}{}
			goto nextSection
		}
		if strings.Contains(name, "go.") ||
			strings.Contains(name, "runtime") ||
			strings.Contains(name, "eh_frame") ||
			strings.Contains(name, ".ctors") ||
			strings.Contains(name, ".dtors") {
			critical[i] = struct{}{}
		}
	nextSection:
	}
	return critical
}

func (p *PEFile) identifyStripSections(force bool, keepResources bool) (removable, keepable []int) {
	rules := GetSectionStripRule()
	protected := p.sectionsReferencedByDataDirectories()
	criticalSections := p.identifyCriticalSections(force, keepResources)
	resourceRule, hasResourceRule := rules[ResourceSections]

	for i := range p.Sections {
		section := &p.Sections[i]
		if _, ok := protected[i]; ok && !force {
			keepable = append(keepable, i)
			continue
		}
		if _, ok := criticalSections[i]; ok {
			keepable = append(keepable, i)
			continue
		}

		if keepResources && hasResourceRule && common.MatchesPattern(section.Name, resourceRule.ExactNames, resourceRule.PrefixNames) {
			keepable = append(keepable, i)
			continue
		}

		isRemovable := false
		if section.Stripped {
			isRemovable = true
		} else if p.isCorruptedSection(*section) {
			isRemovable = true
		} else if force && p.isNullOrZeroSection(*section) {
			isRemovable = true
		} else {
			for sectionType, rule := range rules {
				if p.sectionMatchesRule(sectionType, section, rule, force) {
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

func (p *PEFile) sectionRemoval(force bool, keepResources bool) (*common.OperationResult, error) {
	if len(p.Sections) == 0 {
		return common.NewSkipped("no sections to process"), nil
	}

	originalSize := uint64(len(p.RawData))
	removableSectionIndices, _ := p.identifyStripSections(force, keepResources)

	if len(removableSectionIndices) == 0 {
		return common.NewSkipped("no removable sections found"), nil
	}

	removedRanges := make([]virtualRange, 0, len(removableSectionIndices))
	removedNames := make([]string, 0, len(removableSectionIndices))
	for _, idx := range removableSectionIndices {
		if idx >= 0 && idx < len(p.Sections) {
			section := p.Sections[idx]
			size := section.VirtualSize
			if raw := uint32(section.Size); raw > size {
				size = raw
			}
			if size == 0 {
				size = 1
			}
			end := section.VirtualAddress + size
			if end < section.VirtualAddress {
				end = math.MaxUint32
			}
			removedRanges = append(removedRanges, virtualRange{
				start: section.VirtualAddress,
				end:   end,
			})
			removedNames = append(removedNames, section.Name)
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
	newSections := p.buildNewSectionsWithCorrectVirtualSize(removableSectionIndices, removedRanges)
	if err := p.updateSectionTableWithNewSections(newSections); err != nil {
		return nil, fmt.Errorf("failed to update section table: %w", err)
	}
	if err := p.clearDataDirectoriesForRemovedRVAs(removedRanges); err != nil {
		return nil, fmt.Errorf("failed to clear data directories: %w", err)
	}
	// Update AddressOfEntryPoint if entry point RVA falls in removed sections
	// Calculate how much the entry point needs to shift based on removed virtual ranges
	if err := p.updateEntryPointAfterSectionRemoval(removedRanges); err != nil {
		return nil, fmt.Errorf("failed to update entry point: %w", err)
	}
	metadataDetails, err := p.updateRelocationMetadata(removedNames)
	if err != nil {
		return nil, fmt.Errorf("failed to update relocation metadata: %w", err)
	}
	p.Sections = newSections
	// Recalculate PE header sizes and optionally trim overlay before reporting final size
	// 1) Recalculate SizeOfImage and SizeOfHeaders
	// 2) Zero CheckSum (unsigned binaries) and trim overlay if no Security directory is present
	alignUp32 := func(v, a uint32) uint32 {
		if a == 0 {
			return v
		}
		r := v % a
		if r == 0 {
			return v
		}
		return v + (a - r)
	}

	// Extract SectionAlignment
	extractSectionAlignment := func() uint32 {
		offsets, err := p.calculateOffsets()
		if err != nil {
			return PE_SECTION_ALIGNMENT_DEFAULT
		}
		is64 := p.Is64Bit
		var secAlignOffset int64
		if is64 {
			secAlignOffset = offsets.OptionalHeader + PE64_SECTION_ALIGN
		} else {
			secAlignOffset = offsets.OptionalHeader + PE32_SECTION_ALIGN
		}
		if secAlignOffset+4 > int64(len(p.RawData)) {
			return PE_SECTION_ALIGNMENT_DEFAULT
		}
		return binary.LittleEndian.Uint32(p.RawData[secAlignOffset:])
	}
	sectionAlignment := extractSectionAlignment()
	if sectionAlignment == 0 {
		sectionAlignment = PE_SECTION_ALIGNMENT_DEFAULT
	}

	// Compute SizeOfImage as max end of sections (VA + aligned size)
	var maxEndVA uint32
	for _, s := range p.Sections {
		if s.VirtualSize == 0 && s.Size == 0 {
			continue
		}
		// Use the larger between VirtualSize and raw Size projected to VA
		vs := s.VirtualSize
		if vs < uint32(s.Size) {
			vs = uint32(s.Size)
		}
		end := s.VirtualAddress + alignUp32(vs, sectionAlignment)
		if end > maxEndVA {
			maxEndVA = end
		}
	}
	// Compute SizeOfHeaders: align up to FileAlignment the first section raw offset (or end of section headers)
	var firstRaw uint32 = 0xFFFFFFFF
	for _, s := range p.Sections {
		if s.FileOffset > 0 && (uint32(s.FileOffset) < firstRaw) {
			firstRaw = uint32(s.FileOffset)
		}
	}
	offsets, err2 := p.calculateOffsets()
	var headersEnd uint32
	if err2 == nil {
		headersEnd = uint32(offsets.FirstSectionHdr + int64(len(p.Sections))*PE_SECTION_HEADER_SIZE)
	}
	var sizeOfHeaders uint32
	if firstRaw != 0xFFFFFFFF {
		sizeOfHeaders = alignUp32(firstRaw, fileAlignment)
	} else if headersEnd > 0 {
		sizeOfHeaders = alignUp32(headersEnd, fileAlignment)
	} else {
		sizeOfHeaders = alignUp32(1024, fileAlignment) // conservative fallback
	}

	// Write SizeOfImage, SizeOfHeaders, and zero CheckSum
	if err2 == nil {
		is64 := p.Is64Bit
		var sizeOfImageOff, sizeOfHeadersOff, checkSumOff int64
		if is64 {
			sizeOfImageOff = offsets.OptionalHeader + PE64_SIZE_OF_IMAGE
			sizeOfHeadersOff = offsets.OptionalHeader + PE64_SIZE_OF_HEADERS
			checkSumOff = offsets.OptionalHeader + PE64_CHECKSUM
		} else {
			sizeOfImageOff = offsets.OptionalHeader + PE32_SIZE_OF_IMAGE
			sizeOfHeadersOff = offsets.OptionalHeader + PE32_SIZE_OF_HEADERS
			checkSumOff = offsets.OptionalHeader + PE32_CHECKSUM
		}
		_ = WriteAtOffset(p.RawData, sizeOfImageOff, maxEndVA)
		_ = WriteAtOffset(p.RawData, sizeOfHeadersOff, sizeOfHeaders)
		_ = WriteAtOffset(p.RawData, checkSumOff, uint32(0))
	}

	// Optionally trim overlay if there is no Authenticode (Security Directory empty)
	// IMPORTANT: Skip overlay trimming for packed binaries - packers like UPX store
	// compressed data in the overlay region that extends beyond the last section.
	trimmedOverlay := int64(0)
	if err2 == nil && force && !p.IsPacked {
		// Read Security directory entry (index 4)
		var dataDirsBase int64
		if p.Is64Bit {
			dataDirsBase = offsets.OptionalHeader + PE64_DATA_DIRECTORIES
		} else {
			dataDirsBase = offsets.OptionalHeader + PE32_DATA_DIRECTORIES
		}
		secDirOff := dataDirsBase + int64(IMAGE_DIRECTORY_ENTRY_SECURITY)*IMAGE_SIZEOF_DATA_DIRECTORY
		if secDirOff+8 <= int64(len(p.RawData)) {
			secVA := binary.LittleEndian.Uint32(p.RawData[secDirOff:])
			secSz := binary.LittleEndian.Uint32(p.RawData[secDirOff+4:])
			// If no signature, we can safely trim overlay tail
			if secVA == 0 && secSz == 0 {
				// Minimal file size: max end of sections vs headers
				var maxEndFile int64 = int64(sizeOfHeaders)
				for _, s := range p.Sections {
					if s.Size > 0 {
						end := s.Offset + s.Size
						if end > maxEndFile {
							maxEndFile = end
						}
					}
				}
				if int64(len(p.RawData)) > maxEndFile {
					trimmedOverlay = int64(len(p.RawData)) - maxEndFile
					p.RawData = p.RawData[:maxEndFile]
				}
			}
		}
	}

	newSize := uint64(len(p.RawData))
	removedBytes := int64(originalSize) - int64(newSize)
	if removedBytes < 0 {
		removedBytes = 0
	}
	percent := 0.0
	if originalSize > 0 {
		percent = float64(uint64(removedBytes)) / float64(originalSize) * 100.0
	}

	// Build a detailed, categorized result similar to ELF
	result := common.NewApplied(fmt.Sprintf("removed %d sections", len(removableSectionIndices)), len(removableSectionIndices))
	result.SetCategory("SECTIONS")
	for _, name := range removedNames {
		result.AddDetail(fmt.Sprintf("removed section: %s", name), 1, false)
	}
	result.AddDetail(fmt.Sprintf("size reduced: %d -> %d bytes (%d bytes removed, %.1f%% reduction)", originalSize, newSize, removedBytes, percent), 1, false)
	if trimmedOverlay > 0 {
		result.AddDetail(fmt.Sprintf("trimmed overlay: %d bytes removed (no Authenticode)", trimmedOverlay), 1, false)
	}
	result.AddDetail("updated PE headers: SizeOfImage/SizeOfHeaders recalculated; CheckSum cleared", 1, false)
	for _, warn := range p.validatePostCompact(removedNames) {
		result.AddDetail(warn, 0, true)
	}
	for _, detail := range metadataDetails {
		result.AddDetail(detail, 1, false)
	}
	return result, nil
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
		if err := p.wipeSectionData(&sectionToRemove, ZeroFill); err != nil {
			return fmt.Errorf("failed to fill section %s: %w", sectionToRemove.Name, err)
		}
		p.Sections[sectionIdx].Stripped = true
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

func (p *PEFile) buildNewSectionsWithCorrectVirtualSize(removedIndices []int, removedRanges []virtualRange) []Section {
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
		for _, rng := range removedRanges {
			if rng.start > currentSection.VirtualAddress && rng.start < nextSection.VirtualAddress {
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

func (p *PEFile) clearDataDirectoriesForRemovedRVAs(removedRanges []virtualRange) error {
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
		if rvaFallsInRemovedRange(rva, removedRanges) {
			binary.LittleEndian.PutUint32(p.RawData[entryOffset:], 0)
			binary.LittleEndian.PutUint32(p.RawData[entryOffset+4:], 0)
		}
	}
	return nil
}

func rvaFallsInRemovedRange(rva uint32, ranges []virtualRange) bool {
	for _, rng := range ranges {
		if rva >= rng.start && rva < rng.end {
			return true
		}
	}
	return false
}

// updateEntryPointAfterSectionRemoval adjusts AddressOfEntryPoint if sections before it were removed.
// When sections are removed, the virtual address space compacts, so RVAs after removed sections must shift down.
func (p *PEFile) updateEntryPointAfterSectionRemoval(removedRanges []virtualRange) error {
	if len(removedRanges) == 0 {
		return nil
	}

	originalEntryPoint := p.entryPoint

	// Check if entry point falls within a removed range (invalid after compaction)
	if rvaFallsInRemovedRange(originalEntryPoint, removedRanges) {
		// Entry point is in a removed section - this is critical and should have been caught earlier
		// We can't fix this, just report it
		return fmt.Errorf("entry point 0x%X falls within removed section range", originalEntryPoint)
	}

	// Calculate RVA shift: sum of all removed virtual ranges that start before the entry point
	var rvaShift uint32 = 0
	for _, rng := range removedRanges {
		// Only count ranges that end before or at the entry point
		if rng.end <= originalEntryPoint {
			// The size of this removed range
			removedSize := rng.end - rng.start
			rvaShift += removedSize
		}
	}

	// If no shift needed, we're done
	if rvaShift == 0 {
		return nil
	}

	// Calculate new entry point (shift down by the removed size)
	newEntryPoint := originalEntryPoint - rvaShift

	// Update the in-memory field
	p.entryPoint = newEntryPoint

	// Write back to PE Optional Header in RawData
	offsets, err := p.calculateOffsets()
	if err != nil {
		return fmt.Errorf("calculate offsets: %w", err)
	}

	var entryPointOffset int64
	if p.Is64Bit {
		entryPointOffset = offsets.OptionalHeader + PE64_ENTRY_POINT
	} else {
		entryPointOffset = offsets.OptionalHeader + PE32_ENTRY_POINT
	}

	if err := p.validateOffset(entryPointOffset, 4); err != nil {
		return fmt.Errorf("entry point offset out of bounds: %w", err)
	}

	binary.LittleEndian.PutUint32(p.RawData[entryPointOffset:], newEntryPoint)

	return nil
}

func (p *PEFile) updateRelocationMetadata(removedSections []string) ([]string, error) {
	hasReloc := false
	for _, name := range removedSections {
		trimmed := strings.ToLower(strings.TrimSpace(strings.Trim(name, "\x00")))
		if strings.HasPrefix(trimmed, ".reloc") {
			hasReloc = true
			break
		}
	}
	if !hasReloc {
		return nil, nil
	}

	offsets, err := p.calculateOffsets()
	if err != nil {
		return nil, fmt.Errorf("calculate offsets: %w", err)
	}

	var details []string
	if changed, err := p.setFileHeaderCharacteristic(offsets, pe.IMAGE_FILE_RELOCS_STRIPPED, true); err != nil {
		return nil, fmt.Errorf("set IMAGE_FILE_RELOCS_STRIPPED: %w", err)
	} else if changed {
		details = append(details, "set IMAGE_FILE_RELOCS_STRIPPED flag")
	}
	if changed, err := p.setDLLCharacteristic(offsets, IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE, false); err != nil {
		return nil, fmt.Errorf("clear DYNAMIC_BASE flag: %w", err)
	} else if changed {
		details = append(details, "cleared DYNAMIC_BASE flag (ASLR disabled)")
	}
	return details, nil
}

func (p *PEFile) setFileHeaderCharacteristic(offsets *PEOffsets, mask uint16, enable bool) (bool, error) {
	if offsets == nil {
		return false, fmt.Errorf("file offsets not initialized")
	}
	charOffset := offsets.ELfanew + PE_SIGNATURE_SIZE + PE_CHARACTERISTICS_OFFSET
	if err := p.validateOffset(charOffset, 2); err != nil {
		return false, err
	}
	current := binary.LittleEndian.Uint16(p.RawData[charOffset : charOffset+2])
	updated := current
	if enable {
		updated |= mask
	} else {
		updated &^= mask
	}
	if updated == current {
		return false, nil
	}
	binary.LittleEndian.PutUint16(p.RawData[charOffset:], updated)
	return true, nil
}

func (p *PEFile) setDLLCharacteristic(offsets *PEOffsets, mask uint16, enable bool) (bool, error) {
	if offsets == nil {
		return false, fmt.Errorf("file offsets not initialized")
	}
	var dllOffset int64
	if p.Is64Bit {
		dllOffset = offsets.OptionalHeader + PE64_DLL_CHARACTERISTICS
	} else {
		dllOffset = offsets.OptionalHeader + PE32_DLL_CHARACTERISTICS
	}
	if err := p.validateOffset(dllOffset, 2); err != nil {
		return false, err
	}
	current := binary.LittleEndian.Uint16(p.RawData[dllOffset : dllOffset+2])
	updated := current
	if enable {
		updated |= mask
	} else {
		updated &^= mask
	}
	if updated == current {
		return false, nil
	}
	binary.LittleEndian.PutUint16(p.RawData[dllOffset:], updated)
	return true, nil
}

func (p *PEFile) readTimeDateStamp() (uint32, int64) {
	if len(p.RawData) < PE_DOS_HEADER_SIZE {
		return 0, -1
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	coffHeaderOffset := peHeaderOffset + PE_SIGNATURE_SIZE
	timeDateStampOffset := coffHeaderOffset + PE_TIMESTAMP_OFFSET
	if timeDateStampOffset+4 > int64(len(p.RawData)) {
		return 0, -1
	}
	value := binary.LittleEndian.Uint32(p.RawData[timeDateStampOffset : timeDateStampOffset+4])
	return value, timeDateStampOffset
}

func (p *PEFile) restoreTimeDateStamp(original uint32, offset int64) {
	if offset < 0 {
		return
	}
	_ = WriteAtOffset(p.RawData, offset, original)
}

func (p *PEFile) repackSections(fileAlignment uint32) {
	if len(p.Sections) == 0 {
		return
	}
	if fileAlignment == 0 {
		fileAlignment = PE_FILE_ALIGNMENT_MIN
	}
	minOffset := int64(len(p.RawData))
	for _, s := range p.Sections {
		if s.Offset > 0 && s.Size > 0 && s.Offset < minOffset {
			minOffset = s.Offset
		}
	}
	if minOffset < 0 || minOffset > int64(len(p.RawData)) {
		minOffset = int64(len(p.RawData))
	}
	header := make([]byte, minOffset)
	copy(header, p.RawData[:minOffset])
	source := append([]byte(nil), p.RawData...)
	buffer := header
	current := len(buffer)
	for i := range p.Sections {
		sec := &p.Sections[i]
		if sec.Size <= 0 {
			sec.Offset = 0
			continue
		}
		align := int64(fileAlignment)
		if align == 0 {
			align = int64(PE_FILE_ALIGNMENT_MIN)
		}
		aligned := int(common.AlignUp64(int64(current), align))
		if aligned > current {
			buffer = append(buffer, make([]byte, aligned-current)...)
			current = aligned
		}
		start := int(sec.Offset)
		end := start + int(sec.Size)
		if start < 0 {
			start = 0
		}
		if end > len(source) {
			end = len(source)
		}
		buffer = append(buffer, source[start:end]...)
		sec.Offset = int64(current)
		current += end - start
	}
	p.RawData = buffer
}

func (p *PEFile) validatePostCompact(removedSections []string) []string {
	var warnings []string
	entryVA := p.entryPoint
	valid := false
	for _, sec := range p.Sections {
		if sec.VirtualSize == 0 && sec.Size == 0 {
			continue
		}
		size := sec.VirtualSize
		if size < uint32(sec.Size) {
			size = uint32(sec.Size)
		}
		if entryVA >= sec.VirtualAddress && entryVA < sec.VirtualAddress+size {
			valid = true
			break
		}
	}
	if !valid {
		warnings = append(warnings, fmt.Sprintf("entry point 0x%X no longer maps to remaining sections", entryVA))
	}
	for _, name := range removedSections {
		trimmed := strings.ToLower(strings.TrimSpace(strings.Trim(name, "\x00")))
		switch {
		case strings.HasPrefix(trimmed, ".rsrc"):
			warnings = append(warnings, "resource section removed; manifests/icons may be unavailable")
		case trimmed == ".idata" || trimmed == ".edata":
			warnings = append(warnings, "import/export tables removed; binary may fail to resolve external APIs")
		case trimmed == ".reloc":
			warnings = append(warnings, "relocation data removed; ASLR may fail on some systems")
		}
	}
	return warnings
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

func (p *PEFile) scrubSectionHeaderNames() {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	optionalSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+PE_SIGNATURE_SIZE+PE_OPTSIZE_OFFSET:])
	sectionTableOffset := peHeaderOffset + PE_SIGNATURE_SIZE + PE_FILE_HEADER_SIZE + int64(optionalSize)
	for i := range p.Sections {
		hdr := sectionTableOffset + int64(i*PE_SECTION_HEADER_SIZE)
		if hdr+PE_SECTION_NAME_SIZE > int64(len(p.RawData)) {
			break
		}
		for j := int64(0); j < PE_SECTION_NAME_SIZE; j++ {
			p.RawData[hdr+j] = 0
		}
		p.Sections[i].Name = fmt.Sprintf("sec_%02d", i)
	}
}
