package perw

import (
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"sort"
	"strings"
)

func (p *PEFile) Compact(force bool) (*common.OperationResult, error) {
	if force {
		res, err := p.properSectionRemoval(force)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("physical compaction failed: %v", err)), nil
		}
		return res, nil
	}
	return p.simpleTruncatePE(), nil
}

func (p *PEFile) identifyCriticalSections() map[int]struct{} {
	critical := make(map[int]struct{})

	for i, section := range p.Sections {
		name := strings.ToLower(section.Name)
		switch name {
		case ".text", ".code":
			critical[i] = struct{}{}
		case ".data", ".rdata":
			critical[i] = struct{}{}
		case ".idata":
			critical[i] = struct{}{}
		}
		if strings.Contains(name, "go.") || strings.Contains(name, "runtime") {
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

		if isRemovable {
			removable = append(removable, i)
		} else {
			keepable = append(keepable, i)
		}
	}
	return
}

func (p *PEFile) simpleTruncatePE() *common.OperationResult {
	originalSize := uint64(len(p.RawData))
	var maxOffset int64
	for _, sec := range p.Sections {
		end := sec.Offset + sec.Size
		if end > maxOffset {
			maxOffset = end
		}
	}
	if maxOffset <= 0 || maxOffset > int64(len(p.RawData)) {
		return common.NewSkipped("no truncation possible")
	}
	p.RawData = p.RawData[:maxOffset]
	newSize := uint64(len(p.RawData))
	message := fmt.Sprintf("simple truncate: %d -> %d bytes", originalSize, newSize)
	return common.NewApplied(message, int(originalSize-newSize))
}

func (p *PEFile) sectionsReferencedByDataDirectories() map[int]struct{} {
	const dataDirCount = 16
	protected := make(map[int]struct{}, dataDirCount)
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	var dataDirBase int64
	if p.Is64Bit {
		dataDirBase = optionalHeaderOffset + 112 // PE32+ offset
	} else {
		dataDirBase = optionalHeaderOffset + 96 // PE32 offset
	}
	for i := 0; i < dataDirCount; i++ {
		entryOff := dataDirBase + int64(i*8) // RVA(uint32)+Size(uint32)
		if int(entryOff+8) > len(p.RawData) {
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

func (p *PEFile) properSectionRemoval(force bool) (*common.OperationResult, error) {
	if len(p.Sections) == 0 {
		return common.NewSkipped("no sections to process"), nil
	}

	originalSize := uint64(len(p.RawData))
	removableSectionIndices, _ := p.identifyStripSections(force)

	if len(removableSectionIndices) == 0 {
		return common.NewSkipped("no removable sections found"), nil
	}

	// CORREZIONE 1: Salva gli RVA rimossi PRIMA di modificare p.Sections
	removedRVAs := make(map[uint32]bool)
	removedNames := make([]string, 0, len(removableSectionIndices))
	for _, idx := range removableSectionIndices {
		if idx >= 0 && idx < len(p.Sections) {
			removedRVAs[p.Sections[idx].VirtualAddress] = true
			removedNames = append(removedNames, p.Sections[idx].Name)
		}
	}

	// CORREZIONE 2: Estrai FileAlignment dinamicamente
	fileAlignment, err := p.extractFileAlignment()
	if err != nil {
		return nil, fmt.Errorf("failed to extract file alignment: %w", err)
	}

	// Ordina gli indici delle sezioni rimovibili in ordine decrescente
	sort.Sort(sort.Reverse(sort.IntSlice(removableSectionIndices)))

	totalRemovedSize := int64(0)

	// Rimozione fisica delle sezioni
	for _, sectionIdx := range removableSectionIndices {
		if err := p.removeSingleSection(sectionIdx, &totalRemovedSize, fileAlignment); err != nil {
			return nil, fmt.Errorf("failed to remove section %d: %w", sectionIdx, err)
		}
	}

	// Aggiorna NumberOfSections nel COFF header
	if err := p.updateNumberOfSections(len(p.Sections) - len(removableSectionIndices)); err != nil {
		return nil, fmt.Errorf("failed to update NumberOfSections: %w", err)
	}

	// CORREZIONE 3: Ricalcola VirtualSize prima di aggiornare la section table
	newSections := p.buildNewSectionsWithCorrectVirtualSize(removableSectionIndices, removedRVAs)

	// Aggiorna la section table con le nuove sezioni
	if err := p.updateSectionTableWithNewSections(newSections); err != nil {
		return nil, fmt.Errorf("failed to update section table: %w", err)
	}

	// CORREZIONE 4: Azzera i Data Directories usando gli RVA salvati
	if err := p.clearDataDirectoriesForRemovedRVAs(removedRVAs); err != nil {
		return nil, fmt.Errorf("failed to clear data directories: %w", err)
	}

	// Aggiorna p.Sections
	p.Sections = newSections

	newSize := uint64(len(p.RawData))
	percentage := float64(originalSize-newSize) * 100.0 / float64(originalSize)
	message := fmt.Sprintf("rimozione sezioni: %d -> %d byte (riduzione del %.1f%%), rimosse %d sezioni: %s",
		originalSize, newSize, percentage, len(removableSectionIndices), strings.Join(removedNames, ", "))

	return common.NewApplied(message, len(removableSectionIndices)), nil
}

func (p *PEFile) extractFileAlignment() (uint32, error) {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	fileAlignmentOffset := optionalHeaderOffset + 36

	if fileAlignmentOffset+4 > int64(len(p.RawData)) {
		return 512, nil // Default fallback
	}

	fileAlignment := binary.LittleEndian.Uint32(p.RawData[fileAlignmentOffset:])
	if fileAlignment == 0 || fileAlignment < 512 {
		fileAlignment = 512 // Default minimum
	}

	return fileAlignment, nil
}

func (p *PEFile) removeSingleSection(sectionIdx int, totalRemovedSize *int64, fileAlignment uint32) error {
	if sectionIdx < 0 || sectionIdx >= len(p.Sections) {
		return fmt.Errorf("invalid section index: %d", sectionIdx)
	}

	sectionToRemove := p.Sections[sectionIdx]

	// Se la sezione ha dati fisici, rimuovili dal file
	if sectionToRemove.Offset > 0 && sectionToRemove.Size > 0 {
		// CORREZIONE 2: Usa FileAlignment dinamico invece di 512 fisso
		alignedSize := alignUp64(sectionToRemove.Size, int64(fileAlignment))

		// Rimuovi i dati della sezione dal RawData
		start := int(sectionToRemove.Offset)
		end := int(sectionToRemove.Offset + alignedSize)

		if end > len(p.RawData) {
			end = len(p.RawData)
		}

		// Crea nuovo RawData senza i dati della sezione
		newRawData := make([]byte, len(p.RawData)-(end-start))
		copy(newRawData[:start], p.RawData[:start])
		copy(newRawData[start:], p.RawData[end:])
		p.RawData = newRawData

		// Aggiusta i PointerToRawData delle sezioni che seguono
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
	// Crea una mappa degli indici rimossi per un accesso veloce
	removedMap := make(map[int]bool)
	for _, idx := range removedIndices {
		removedMap[idx] = true
	}

	// Crea nuova lista di sezioni senza quelle rimosse
	newSections := make([]Section, 0, len(p.Sections)-len(removedIndices))
	for i, section := range p.Sections {
		if !removedMap[i] {
			newSections = append(newSections, section)
		}
	}

	// CORREZIONE 3: Ricalcola VirtualSize per le sezioni che precedono una rimossa
	for i := 0; i < len(newSections)-1; i++ {
		currentSection := &newSections[i]
		nextSection := &newSections[i+1]

		// Se tra currentSection e nextSection c'era una sezione rimossa,
		// dobbiamo aggiustare la VirtualSize di currentSection
		hasRemovedSectionBetween := false
		for rva := range removedRVAs {
			if rva > currentSection.VirtualAddress && rva < nextSection.VirtualAddress {
				hasRemovedSectionBetween = true
				break
			}
		}

		if hasRemovedSectionBetween {
			// Ricalcola VirtualSize = VA_next - VA_this
			currentSection.VirtualSize = nextSection.VirtualAddress - currentSection.VirtualAddress
		}
	}

	return newSections
}

func (p *PEFile) updateSectionTableWithNewSections(newSections []Section) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	sizeOfOptionalHeader := int64(binary.LittleEndian.Uint16(p.RawData[coffHeaderOffset+16:]))
	sectionTableOffset := optionalHeaderOffset + sizeOfOptionalHeader

	// CORREZIONE 5: Azzera l'intera section table originale
	originalSectionCount := len(p.Sections)
	sectionTableSize := originalSectionCount * 40
	for i := 0; i < sectionTableSize; i++ {
		if sectionTableOffset+int64(i) < int64(len(p.RawData)) {
			p.RawData[sectionTableOffset+int64(i)] = 0
		}
	}

	// Scrivi la nuova section table con le VirtualSize corrette
	for i, section := range newSections {
		hdrOff := sectionTableOffset + int64(i*40)
		if hdrOff+40 > int64(len(p.RawData)) {
			break
		}

		// Nome sezione (8 byte)
		nameBytes := make([]byte, 8)
		copy(nameBytes, section.Name)
		copy(p.RawData[hdrOff:hdrOff+8], nameBytes)

		// CORREZIONE 3: Scrivi la VirtualSize corretta
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+8:], section.VirtualSize)
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+12:], section.VirtualAddress) // NON CAMBIA
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+16:], uint32(section.Size))
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+20:], uint32(section.Offset)) // Aggiustato
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+24:], section.PointerToRelocations)
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+28:], section.PointerToLineNumbers)
		binary.LittleEndian.PutUint16(p.RawData[hdrOff+32:], section.NumberOfRelocations)
		binary.LittleEndian.PutUint16(p.RawData[hdrOff+34:], section.NumberOfLineNumbers)
		binary.LittleEndian.PutUint32(p.RawData[hdrOff+36:], section.Flags)
	}

	return nil
}

func (p *PEFile) clearDataDirectoriesForRemovedRVAs(removedRVAs map[uint32]bool) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20

	var dataDirectoryOffset int64
	if p.Is64Bit {
		dataDirectoryOffset = optionalHeaderOffset + 112
	} else {
		dataDirectoryOffset = optionalHeaderOffset + 96
	}

	// CORREZIONE 4: Usa gli RVA salvati prima della modifica
	for i := 0; i < 16; i++ {
		entryOffset := dataDirectoryOffset + int64(i*8)
		if entryOffset+8 > int64(len(p.RawData)) {
			break
		}

		rva := binary.LittleEndian.Uint32(p.RawData[entryOffset:])
		if rva == 0 {
			continue
		}

		// Se l'RVA corrisponde esattamente a una sezione rimossa, azzeralo
		if removedRVAs[rva] {
			binary.LittleEndian.PutUint32(p.RawData[entryOffset:], 0)
			binary.LittleEndian.PutUint32(p.RawData[entryOffset+4:], 0)
		}
	}

	return nil
}

func (p *PEFile) updateNumberOfSections(newCount int) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	numberOfSectionsOffset := coffHeaderOffset + 2

	if numberOfSectionsOffset+2 > int64(len(p.RawData)) {
		return fmt.Errorf("NumberOfSections offset out of bounds")
	}

	binary.LittleEndian.PutUint16(p.RawData[numberOfSectionsOffset:], uint16(newCount))
	return nil
}
