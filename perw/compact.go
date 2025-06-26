package perw

import (
	"fmt"
	"gosstrip/common"
	"strings"
)

// Compatta il file PE senza stripping
func (p *PEFile) CompactPE() (*common.OperationResult, error) {
	originalSize := uint64(len(p.RawData))

	// Perform simple truncation compaction only
	compactResult, err := p.SimpleTruncationPE()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("compaction failed: %v", err)), nil
	}

	if !compactResult.Applied {
		return common.NewSkipped("no sections suitable for compaction"), nil
	}

	newSize := uint64(len(p.RawData))
	savedBytes := originalSize - newSize
	percentage := float64(savedBytes) * 100.0 / float64(originalSize)

	message := fmt.Sprintf("PE compaction: %d -> %d bytes (%.1f%% reduction); %s",
		originalSize, newSize, percentage, compactResult.Message)

	return common.NewApplied(message, compactResult.Count), nil
}

// Compatta il PE rimuovendo sezioni discardable (se sicuro)
func (p *PEFile) SimpleTruncationPE() (*common.OperationResult, error) {
	if len(p.Sections) == 0 {
		return common.NewSkipped("no sections to compact"), nil
	}

	originalSize := uint64(len(p.RawData))

	removableSections := []int{}
	keptSections := []int{}
	for i, section := range p.Sections {
		isDiscardable := (section.Flags & 0x02000000) != 0
		isRelocation := strings.Contains(strings.ToLower(section.Name), ".reloc")
		if isDiscardable && !isRelocation {
			removableSections = append(removableSections, i)
		} else {
			keptSections = append(keptSections, i)
		}
	}

	if len(removableSections) == 0 {
		return common.NewSkipped("no discardable sections found"), nil
	}

	removedSectionNames := make([]string, 0, len(removableSections))
	for _, idx := range removableSections {
		removedSectionNames = append(removedSectionNames, p.Sections[idx].Name)
	}

	lastEssentialOffset := uint64(0)
	for _, keptIdx := range keptSections {
		section := p.Sections[keptIdx]
		if section.Offset > 0 && section.Size > 0 {
			end := uint64(section.Offset) + uint64(section.Size)
			if end > lastEssentialOffset {
				lastEssentialOffset = end
			}
		}
	}
	lastEssentialOffset = (lastEssentialOffset + 511) &^ 511

	if lastEssentialOffset >= uint64(len(p.RawData)) {
		return common.NewSkipped("cannot compact - essential sections span entire file"), nil
	}

	// Get PE structure information for header updates
	if len(p.RawData) < 64 {
		return nil, fmt.Errorf("file too small for PE structure")
	}

	peHeaderOffset := uint32(p.RawData[0x3C]) | uint32(p.RawData[0x3D])<<8 |
		uint32(p.RawData[0x3E])<<16 | uint32(p.RawData[0x3F])<<24

	if peHeaderOffset+24 > uint32(len(p.RawData)) {
		return nil, fmt.Errorf("invalid PE header offset")
	}

	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	optionalHeaderSize := uint16(p.RawData[coffHeaderOffset+16]) | uint16(p.RawData[coffHeaderOffset+17])<<8
	sectionTableOffset := optionalHeaderOffset + uint32(optionalHeaderSize)
	sectionTableEnd := sectionTableOffset + uint32(len(p.Sections)*40)

	minFileSize := uint64(sectionTableEnd)
	if lastEssentialOffset < minFileSize {
		lastEssentialOffset = minFileSize
		lastEssentialOffset = (lastEssentialOffset + 511) &^ 511
	}

	if lastEssentialOffset >= uint64(len(p.RawData)) {
		return common.NewSkipped("cannot compact - would truncate essential data"), nil
	}

	isGoExecutable := false
	for _, name := range removedSectionNames {
		if strings.HasPrefix(name, ".zdebug_") {
			isGoExecutable = true
			break
		}
	}

	if isGoExecutable {
		savedSpace := uint64(0)
		for _, idx := range removableSections {
			section := p.Sections[idx]
			if section.Offset > 0 && section.Size > 0 {
				savedSpace += uint64(section.Size)
			}
		}
		return common.NewSkipped(fmt.Sprintf("Go executable detected - conservative mode (would save %d bytes)", savedSpace)), nil
	}

	for _, idx := range removableSections {
		section := p.Sections[idx]
		if section.Offset > 0 && section.Size > 0 {
			start := section.Offset
			end := start + section.Size
			if end <= int64(len(p.RawData)) {
				for i := start; i < end; i++ {
					p.RawData[i] = 0
				}
			}
		}
	}

	// Update section count in COFF header to reflect kept sections only
	newSectionCount := uint16(len(keptSections))
	p.RawData[coffHeaderOffset+2] = byte(newSectionCount)
	p.RawData[coffHeaderOffset+3] = byte(newSectionCount >> 8)

	if !isGoExecutable && coffHeaderOffset+16 <= uint32(len(p.RawData)) {
		p.RawData[coffHeaderOffset+8] = 0
		p.RawData[coffHeaderOffset+9] = 0
		p.RawData[coffHeaderOffset+10] = 0
		p.RawData[coffHeaderOffset+11] = 0
		p.RawData[coffHeaderOffset+12] = 0
		p.RawData[coffHeaderOffset+13] = 0
		p.RawData[coffHeaderOffset+14] = 0
		p.RawData[coffHeaderOffset+15] = 0
	}

	for _, idx := range removableSections {
		headerOffset := sectionTableOffset + uint32(idx*40)
		if headerOffset+40 <= uint32(len(p.RawData)) {
			for i := uint32(0); i < 40; i++ {
				p.RawData[headerOffset+i] = 0
			}
		}
	}

	maxKeptIndex := -1
	for _, keptIdx := range keptSections {
		if keptIdx > maxKeptIndex {
			maxKeptIndex = keptIdx
		}
	}
	if len(keptSections) != maxKeptIndex+1 {
		message := fmt.Sprintf("non-contiguous sections detected - zeroed %d sections: %s",
			len(removableSections), strings.Join(removedSectionNames, ", "))
		return common.NewApplied(message, len(removableSections)), nil
	}

	p.RawData = p.RawData[:lastEssentialOffset]
	newSections := make([]Section, 0, len(keptSections))
	for _, keptIdx := range keptSections {
		newSections = append(newSections, p.Sections[keptIdx])
	}
	p.Sections = newSections
	newSize := uint64(len(p.RawData))
	savedBytes := originalSize - newSize
	percentage := float64(savedBytes) * 100.0 / float64(originalSize)
	message := fmt.Sprintf("simple truncation: %d -> %d bytes (%.1f%% reduction), removed %d sections: %s",
		originalSize, newSize, percentage, len(removableSections), strings.Join(removedSectionNames, ", "))
	return common.NewApplied(message, len(removableSections)), nil
}

// Calcola quanto spazio si potrebbe risparmiare con la compattazione
func (p *PEFile) CalculateCompactableSpace() (uint64, []string, error) {
	if len(p.Sections) == 0 {
		return 0, nil, fmt.Errorf("no sections to analyze")
	}

	var compactableSpace uint64
	var compactableSections []string

	for _, section := range p.Sections {
		// Check if section has DISCARDABLE flag (0x02000000)
		isDiscardable := (section.Flags & 0x02000000) != 0
		isRelocation := strings.Contains(strings.ToLower(section.Name), ".reloc")

		if isDiscardable && !isRelocation && section.Size > 0 {
			compactableSpace += uint64(section.Size)
			compactableSections = append(compactableSections, section.Name)
		}
	}

	return compactableSpace, compactableSections, nil
}

// Verifica se la compattazione è sicura per questo PE
func (p *PEFile) ValidateCompactionSafety() (bool, string, error) {
	if len(p.Sections) == 0 {
		return false, "no sections to validate", nil
	}

	// Check for Go executable characteristics
	hasGoSections := false
	for _, section := range p.Sections {
		if strings.HasPrefix(section.Name, ".zdebug_") ||
			strings.HasPrefix(section.Name, ".go") {
			hasGoSections = true
			break
		}
	}

	if hasGoSections {
		return false, "Go executable detected - compaction may corrupt string tables", nil
	}

	// Check for complex section layouts
	executableSections := 0
	for _, section := range p.Sections {
		if (section.Flags & 0x20000000) != 0 { // IMAGE_SCN_MEM_EXECUTE
			executableSections++
		}
	}

	if executableSections > 3 {
		return false, "complex executable layout detected - compaction may be risky", nil
	}

	return true, "compaction appears safe", nil
}
