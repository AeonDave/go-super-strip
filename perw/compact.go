package perw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"sort"
	"strings"
)

type compactionInfo struct {
	keepableSectionIndices []int
	keepableSections       []Section
	sectionDataMap         map[int][]byte
	fileAlignment          uint32
	sectionAlignment       uint32
	newSizeOfHeaders       uint32
	removedNames           []string
	originalSections       []Section
}

func (p *PEFile) Compact(force bool) (*common.OperationResult, error) {
	if force {
		res, err := p.physicalCompactPE(force)
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
			if strings.ToLower(s.Name) == ".reloc" {
				continue
			}
			if s.VirtualAddress <= rva && rva < s.VirtualAddress+s.VirtualSize {
				protected[idx] = struct{}{}
				break
			}
		}
	}
	return protected
}

func (p *PEFile) physicalCompactPE(force bool) (*common.OperationResult, error) {
	if len(p.Sections) == 0 {
		return common.NewSkipped("no sections to process"), nil
	}
	originalSize := uint64(len(p.RawData))
	originalSections := make([]Section, len(p.Sections))
	copy(originalSections, p.Sections)
	removableSectionIndices, keepableSectionIndices := p.identifyStripSections(force)
	if len(removableSectionIndices) == 0 {
		return common.NewSkipped("no removable sections found"), nil
	}
	if len(keepableSectionIndices) == 0 {
		return common.NewSkipped("no sections to keep after compaction"), nil
	}
	compactInfo, err := p.prepareCompaction(originalSections, keepableSectionIndices, removableSectionIndices)
	if err != nil {
		return nil, fmt.Errorf("preparation failed: %w", err)
	}
	if err := p.executeCompaction(compactInfo); err != nil {
		return nil, fmt.Errorf("execution failed: %w", err)
	}
	if err := p.finalizeCompaction(removableSectionIndices, originalSections); err != nil {
		return nil, fmt.Errorf("finalization failed: %w", err)
	}
	if err := p.validatePEAfterCompaction(); err != nil {
		return nil, fmt.Errorf("PE validation failed after compaction: %w", err)
	}
	return p.generateCompactionResult(originalSize, removableSectionIndices, compactInfo.removedNames), nil
}

func (p *PEFile) prepareCompaction(originalSections []Section, keepableSectionIndices, removableSectionIndices []int) (*compactionInfo, error) {
	info := &compactionInfo{
		keepableSectionIndices: keepableSectionIndices,
		sectionDataMap:         make(map[int][]byte),
		removedNames:           make([]string, 0, len(removableSectionIndices)),
		originalSections:       originalSections,
	}
	for _, idx := range removableSectionIndices {
		info.removedNames = append(info.removedNames, p.Sections[idx].Name)
	}
	keepableIndexMap := make(map[int]bool)
	for _, idx := range keepableSectionIndices {
		keepableIndexMap[idx] = true
	}
	sort.Ints(info.keepableSectionIndices)
	for _, idx := range info.keepableSectionIndices {
		info.keepableSections = append(info.keepableSections, originalSections[idx])
	}
	if err := p.extractAlignmentParameters(&info.fileAlignment, &info.sectionAlignment); err != nil {
		return nil, err
	}
	p.preserveSectionData(originalSections, keepableIndexMap, info.sectionDataMap)
	info.newSizeOfHeaders = p.calculateNewHeaderSize(info.fileAlignment, len(info.keepableSections))
	p.recalculateSectionOffsets(info.keepableSections, info.fileAlignment, info.newSizeOfHeaders)
	return info, nil
}

func (p *PEFile) extractAlignmentParameters(fileAlignment, sectionAlignment *uint32) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20

	*sectionAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+32:])
	*fileAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+36:])

	if *fileAlignment == 0 || *fileAlignment < 512 {
		*fileAlignment = 512
	}

	return nil
}

func (p *PEFile) preserveSectionData(originalSections []Section, keepableIndexMap map[int]bool, sectionDataMap map[int][]byte) {
	for originalIdx, sec := range originalSections {
		if keepableIndexMap[originalIdx] {
			if sec.Offset > 0 && sec.Size > 0 && sec.Offset+sec.Size <= int64(len(p.RawData)) {
				data := make([]byte, sec.Size)
				copy(data, p.RawData[sec.Offset:sec.Offset+sec.Size])
				sectionDataMap[originalIdx] = data
			}
		}
	}
}

func (p *PEFile) calculateNewHeaderSize(fileAlignment uint32, numSections int) uint32 {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	sizeOfOptionalHeader := int64(binary.LittleEndian.Uint16(p.RawData[coffHeaderOffset+16:]))
	sectionTableOffset := optionalHeaderOffset + sizeOfOptionalHeader
	minHeaderSize := sectionTableOffset + int64(numSections*40) + 4
	return alignUp(uint32(minHeaderSize), fileAlignment)
}

func (p *PEFile) recalculateSectionOffsets(keepableSections []Section, fileAlignment, newSizeOfHeaders uint32) {
	currentFileOffset := int64(newSizeOfHeaders)
	for i := range keepableSections {
		sec := &keepableSections[i]
		sec.Offset = alignUp64(currentFileOffset, int64(fileAlignment))
		sizeOnDisk := alignUp64(sec.Size, int64(fileAlignment))
		currentFileOffset = sec.Offset + sizeOnDisk
	}
}

func (p *PEFile) executeCompaction(info *compactionInfo) error {
	finalFileSize := p.calculateFinalFileSizeWithPadding(info.keepableSections, info.fileAlignment)
	newRawData := make([]byte, finalFileSize)
	headerSize := int64(info.newSizeOfHeaders)
	if headerSize > int64(len(p.RawData)) {
		headerSize = int64(len(p.RawData))
	}
	copy(newRawData[:headerSize], p.RawData[:headerSize])
	if err := p.updatePEHeadersInNewBuffer(newRawData, info); err != nil {
		return fmt.Errorf("failed to update headers: %w", err)
	}
	if err := p.updateSectionTableInNewBuffer(newRawData, info); err != nil {
		return fmt.Errorf("failed to update section table: %w", err)
	}
	if err := p.copySectionData(newRawData, info.keepableSections, info.keepableSectionIndices, info.sectionDataMap); err != nil {
		return err
	}
	fmt.Printf("DEBUG: Prima dell'aggiornamento - DOS: %02x %02x\n", newRawData[0], newRawData[1])
	p.RawData = newRawData
	p.Sections = info.keepableSections
	p.debugPEStructure()
	return nil
}

func (p *PEFile) calculateFinalFileSizeWithPadding(keepableSections []Section, fileAlignment uint32) int64 {
	if len(keepableSections) == 0 {
		return 0
	}
	lastSection := keepableSections[len(keepableSections)-1]
	lastSectionAlignedSize := alignUp64(lastSection.Size, int64(fileAlignment))
	lastSectionEnd := lastSection.Offset + lastSectionAlignedSize
	return alignUp64(lastSectionEnd, int64(fileAlignment))
}

func (p *PEFile) copySectionData(newRawData []byte, keepableSections []Section, keepableSectionIndices []int, sectionDataMap map[int][]byte) error {
	for i, originalIdx := range keepableSectionIndices {
		sec := keepableSections[i]
		data, ok := sectionDataMap[originalIdx]
		if !ok {
			continue
		}

		end := sec.Offset + int64(len(data))
		if end > int64(len(newRawData)) {
			return fmt.Errorf("section %s exceeds file size", sec.Name)
		}

		copy(newRawData[sec.Offset:end], data)
	}
	return nil
}

func (p *PEFile) finalizeCompaction(removableSectionIndices []int, originalSections []Section) error {
	p.clearInvalidDataDirectories(removableSectionIndices, originalSections)
	if err := p.validateEntryPoint(); err != nil {
		return fmt.Errorf("invalid entry point: %w", err)
	}
	if err := p.validateDataDirectoriesAfterCompaction(); err != nil {
		return fmt.Errorf("data directories validation failed: %w", err)
	}
	return nil
}

func (p *PEFile) updatePEHeadersInNewBuffer(data []byte, info *compactionInfo) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	binary.LittleEndian.PutUint16(data[coffHeaderOffset+2:], uint16(len(info.keepableSections)))

	characteristics := binary.LittleEndian.Uint16(data[coffHeaderOffset+18:])
	hasRelocSection := false
	for _, sec := range info.keepableSections {
		if strings.ToLower(sec.Name) == ".reloc" {
			hasRelocSection = true
			break
		}
	}
	if !hasRelocSection {
		characteristics |= 0x0001 // IMAGE_FILE_RELOCS_STRIPPED
		binary.LittleEndian.PutUint16(data[coffHeaderOffset+18:], characteristics)
	}

	binary.LittleEndian.PutUint32(data[coffHeaderOffset+8:], 0)  // PointerToSymbolTable
	binary.LittleEndian.PutUint32(data[coffHeaderOffset+12:], 0) // NumberOfSymbols
	//binary.LittleEndian.PutUint16(data[coffHeaderOffset+2:], uint16(len(info.keepableSections)))
	if len(info.keepableSections) > 0 {
		lastSection := info.keepableSections[len(info.keepableSections)-1]
		newSizeOfImage := alignUp(lastSection.VirtualAddress+lastSection.VirtualSize, info.sectionAlignment)
		binary.LittleEndian.PutUint32(data[optionalHeaderOffset+56:], newSizeOfImage)
	}
	binary.LittleEndian.PutUint32(data[optionalHeaderOffset+60:], info.newSizeOfHeaders)
	return nil
}

func (p *PEFile) shouldClearRelocations(sectionName string) bool {
	name := strings.ToLower(sectionName)
	switch name {
	case ".text", ".code", ".data", ".rdata", ".idata":
		return false
	case ".reloc":
		return false
	}
	if strings.Contains(name, "debug") || strings.Contains(name, "symtab") {
		return true
	}
	return false
}

func (p *PEFile) updateSectionTableInNewBuffer(data []byte, info *compactionInfo) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	sizeOfOptionalHeader := int64(binary.LittleEndian.Uint16(data[coffHeaderOffset+16:]))
	sectionTableOffset := optionalHeaderOffset + sizeOfOptionalHeader

	for i, originalIdx := range info.keepableSectionIndices {
		sec := info.keepableSections[i]
		hdrOff := sectionTableOffset + int64(i*40)
		if hdrOff+40 > int64(len(data)) {
			return fmt.Errorf("section table exceeds file bounds")
		}
		originalSec := info.originalSections[originalIdx]
		nameBytes := make([]byte, 8)
		copy(nameBytes, sec.Name)
		copy(data[hdrOff:hdrOff+8], nameBytes)
		binary.LittleEndian.PutUint32(data[hdrOff+8:], sec.VirtualSize)
		binary.LittleEndian.PutUint32(data[hdrOff+12:], sec.VirtualAddress)
		sizeRaw := alignUp(uint32(sec.Size), info.fileAlignment)
		binary.LittleEndian.PutUint32(data[hdrOff+16:], sizeRaw)
		binary.LittleEndian.PutUint32(data[hdrOff+20:], uint32(sec.Offset))

		if p.shouldClearRelocations(sec.Name) {
			// Azzera relocazioni per sezioni modificate
			binary.LittleEndian.PutUint32(data[hdrOff+24:], 0) // PointerToRelocations
			binary.LittleEndian.PutUint32(data[hdrOff+28:], 0) // PointerToLineNumbers
			binary.LittleEndian.PutUint16(data[hdrOff+32:], 0) // NumberOfRelocations
			binary.LittleEndian.PutUint16(data[hdrOff+34:], 0) // NumberOfLineNumbers
		} else {
			// Mantieni relocazioni originali per sezioni critiche
			binary.LittleEndian.PutUint32(data[hdrOff+24:], originalSec.PointerToRelocations)
			binary.LittleEndian.PutUint32(data[hdrOff+28:], originalSec.PointerToLineNumbers)
			binary.LittleEndian.PutUint16(data[hdrOff+32:], originalSec.NumberOfRelocations)
			binary.LittleEndian.PutUint16(data[hdrOff+34:], originalSec.NumberOfLineNumbers)
		}
		binary.LittleEndian.PutUint32(data[hdrOff+36:], sec.Flags)
	}

	totalOriginalSections := len(p.Sections)
	for i := len(info.keepableSections); i < totalOriginalSections; i++ {
		hdrOff := sectionTableOffset + int64(i*40)
		if hdrOff+40 <= int64(len(data)) {
			for j := 0; j < 40; j++ {
				data[hdrOff+int64(j)] = 0
			}
		}
	}

	return nil
}

func (p *PEFile) generateCompactionResult(originalSize uint64, removableSectionIndices []int, removedNames []string) *common.OperationResult {
	newSize := uint64(len(p.RawData))
	percentage := float64(originalSize-newSize) * 100.0 / float64(originalSize)
	message := fmt.Sprintf("compattazione fisica: %d -> %d byte (riduzione del %.1f%%), rimosse %d sezioni: %s",
		originalSize, newSize, percentage, len(removableSectionIndices), strings.Join(removedNames, ", "))
	return common.NewApplied(message, len(removableSectionIndices))
}

func (p *PEFile) clearInvalidDataDirectories(removedIndices []int, originalSections []Section) {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20

	var numberOfRvaAndSizes uint32
	var dataDirectoryOffset int64

	if p.Is64Bit {
		numberOfRvaAndSizes = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+108:])
		dataDirectoryOffset = optionalHeaderOffset + 112
	} else {
		numberOfRvaAndSizes = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+92:])
		dataDirectoryOffset = optionalHeaderOffset + 96
	}

	if numberOfRvaAndSizes > 16 {
		numberOfRvaAndSizes = 16
	}

	removedRanges := make([]struct{ start, end uint32 }, 0, len(removedIndices))
	for _, idx := range removedIndices {
		if idx >= 0 && idx < len(originalSections) {
			sec := originalSections[idx]
			removedRanges = append(removedRanges, struct{ start, end uint32 }{
				start: sec.VirtualAddress,
				end:   sec.VirtualAddress + sec.VirtualSize,
			})
		}
	}

	// Se non ci sono sezioni rimosse, niente da fare
	if len(removedRanges) == 0 {
		return
	}

	// Controlla ogni Data Directory
	for i := uint32(0); i < numberOfRvaAndSizes; i++ {
		entryOffset := dataDirectoryOffset + int64(i*8)
		if entryOffset+8 > int64(len(p.RawData)) {
			break
		}

		rva := binary.LittleEndian.Uint32(p.RawData[entryOffset:])
		size := binary.LittleEndian.Uint32(p.RawData[entryOffset+4:])

		if rva == 0 {
			continue
		}

		// Controlla se l'RVA (o parte della struttura) cade in un range rimosso
		structEnd := rva + size
		for _, r := range removedRanges {
			// Verifica sovrapposizione: la struttura interseca il range rimosso?
			if (rva >= r.start && rva < r.end) ||
				(structEnd > r.start && structEnd <= r.end) ||
				(rva < r.start && structEnd > r.end) {
				// Azzera la directory se interseca con una sezione rimossa
				binary.LittleEndian.PutUint32(p.RawData[entryOffset:], 0)
				binary.LittleEndian.PutUint32(p.RawData[entryOffset+4:], 0)
				break
			}
		}
	}
}

func (p *PEFile) validateEntryPoint() error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20
	epRVAOffset := optionalHeaderOffset + 40
	if epRVAOffset+4 > int64(len(p.RawData)) {
		return fmt.Errorf("entry point offset out of bounds")
	}
	epRVA := binary.LittleEndian.Uint32(p.RawData[epRVAOffset:])
	if epRVA == 0 {
		return nil
	}
	for _, sec := range p.Sections {
		if sec.VirtualAddress <= epRVA && epRVA < sec.VirtualAddress+sec.VirtualSize {
			return nil
		}
	}
	return fmt.Errorf("entry point RVA 0x%X points to removed section", epRVA)
}

func (p *PEFile) validateDataDirectoriesAfterCompaction() error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20

	var numberOfRvaAndSizes uint32
	var dataDirectoryOffset int64

	if p.Is64Bit {
		numberOfRvaAndSizes = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+108:])
		dataDirectoryOffset = optionalHeaderOffset + 112
	} else {
		numberOfRvaAndSizes = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+92:])
		dataDirectoryOffset = optionalHeaderOffset + 96
	}

	if numberOfRvaAndSizes > 16 {
		numberOfRvaAndSizes = 16
	}

	for i := uint32(0); i < numberOfRvaAndSizes; i++ {
		entryOffset := dataDirectoryOffset + int64(i*8)
		rva := binary.LittleEndian.Uint32(p.RawData[entryOffset:])
		size := binary.LittleEndian.Uint32(p.RawData[entryOffset+4:])

		if rva == 0 {
			continue // Entry vuota, ok
		}

		// Verifica che l'RVA punti a una sezione valida
		foundValidSection := false
		for _, sec := range p.Sections {
			if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
				// Verifica che la struttura completa sia contenuta nella sezione
				if rva+size <= sec.VirtualAddress+sec.VirtualSize {
					foundValidSection = true
					break
				}
			}
		}

		if !foundValidSection {
			// Se l'RVA non è valido, azzeralo per evitare crashes
			binary.LittleEndian.PutUint32(p.RawData[entryOffset:], 0)
			binary.LittleEndian.PutUint32(p.RawData[entryOffset+4:], 0)
		}
	}

	return nil
}

func (p *PEFile) validatePEAfterCompaction() error {
	if len(p.RawData) < 64 || p.RawData[0] != 'M' || p.RawData[1] != 'Z' {
		return fmt.Errorf("invalid DOS signature")
	}
	peOffset := binary.LittleEndian.Uint32(p.RawData[0x3C:0x40])
	if int(peOffset+24) > len(p.RawData) ||
		!bytes.Equal(p.RawData[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
		return fmt.Errorf("invalid PE signature")
	}
	return nil
}

func (p *PEFile) debugPEStructure() {
	if len(p.RawData) < 64 {
		fmt.Printf("DEBUG: File troppo piccolo: %d bytes\n", len(p.RawData))
		return
	}
	if p.RawData[0] != 'M' || p.RawData[1] != 'Z' {
		fmt.Printf("DEBUG: DOS signature invalida: %02x %02x\n", p.RawData[0], p.RawData[1])
		return
	}
	peOffset := binary.LittleEndian.Uint32(p.RawData[0x3C:0x40])
	fmt.Printf("DEBUG: PE offset: 0x%x\n", peOffset)

	if int(peOffset+4) > len(p.RawData) {
		fmt.Printf("DEBUG: PE offset fuori dai limiti\n")
		return
	}
	peSignature := p.RawData[peOffset : peOffset+4]
	fmt.Printf("DEBUG: PE signature: %c%c%02x%02x\n", peSignature[0], peSignature[1], peSignature[2], peSignature[3])
}
