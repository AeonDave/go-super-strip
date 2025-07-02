package perw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"os"
)

func findPESignature(data []byte) int64 {
	peSignature := []byte{'P', 'E', 0, 0}
	for i := int64(0); i < int64(len(data))-4; i++ {
		if bytes.Equal(data[i:i+4], peSignature) {
			return i
		}
	}
	return -1
}

func calculateAlignedSize(size, alignment uint32) uint32 {
	return (size + alignment - 1) &^ (alignment - 1)
}

func findNewSectionOffset(fileSize int64, fileAlignment uint32) int64 {
	return (fileSize + int64(fileAlignment) - 1) &^ (int64(fileAlignment) - 1)
}

func writeSectionContent(rawData []byte, newOffset int64, content []byte, alignedSize uint32) {
	copy(rawData[newOffset:], content)
	for i := newOffset + int64(len(content)); i < newOffset+int64(alignedSize); i++ {
		rawData[i] = 0
	}
}

func (p *PEFile) AddHexSection(sectionName string, dataOrFile string, password string) error {
	fileStat, err := os.Stat(dataOrFile)
	isFile := err == nil && !fileStat.IsDir()

	var finalContent []byte
	if isFile {
		finalContent, err = common.ProcessFileForInsertion(dataOrFile, password)
		if err != nil {
			return fmt.Errorf("failed to process file for insertion: %w", err)
		}
	} else {
		finalContent, err = common.ProcessStringForInsertion(dataOrFile, password)
		if err != nil {
			return fmt.Errorf("failed to process string for insertion: %w", err)
		}
	}
	return p.addSectionWithContent(sectionName, finalContent, password != "")
}

func (p *PEFile) addSectionWithContent(sectionName string, content []byte, encrypted bool) error {
	fileAlignment, sectionAlignment, peHeaderOffset, _, err := p.getPEAlignments()
	if err != nil {
		return fmt.Errorf("failed to extract alignments: %w", err)
	}
	if err := p.ensureSpaceForNewSectionHeader(); err != nil {
		return fmt.Errorf("cannot expand headers: %w", err)
	}
	rawDataSize := uint32(len(content))
	alignedSize := calculateAlignedSize(rawDataSize, fileAlignment)
	newOffset := findNewSectionOffset(int64(len(p.RawData)), fileAlignment)
	newVirtualAddress := p.findNewSectionRVA(sectionAlignment)
	p.extendRawDataIfNeeded(newOffset + int64(alignedSize))
	writeSectionContent(p.RawData, newOffset, content, alignedSize)
	newSection := Section{
		Name:           sectionName,
		Offset:         newOffset,
		Size:           int64(alignedSize),
		VirtualAddress: newVirtualAddress,
		VirtualSize:    rawDataSize,
		Index:          len(p.Sections),
		Flags:          0x40000040, // Initialized data, readable
		RVA:            newVirtualAddress,
	}
	p.Sections = append(p.Sections, newSection)
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+20 : peHeaderOffset+22])
	if err := p.updateSectionHeaders(peHeaderOffset, optionalHeaderSize); err != nil {
		p.Sections = p.Sections[:len(p.Sections)-1]
		return fmt.Errorf("header modification failed: %w", err)
	}
	if err := p.updateSizeOfImage(sectionAlignment, newVirtualAddress, rawDataSize); err != nil {
		p.Sections = p.Sections[:len(p.Sections)-1]
		return fmt.Errorf("SizeOfImage update failed: %w", err)
	}
	if err := p.fixCOFFHeaderAfterStripping(); err != nil {
		fmt.Printf("⚠️  COFF header repair failed: %v\n", err)
	}
	fmt.Printf("Hex section '%s' added successfully", sectionName)
	if encrypted {
		fmt.Printf(" (encrypted)")
	}
	fmt.Printf("\n")
	return nil
}

func (p *PEFile) getPEAlignments() (fileAlignment, sectionAlignment uint32, peHeaderOffset, optionalHeaderOffset int64, err error) {
	if len(p.RawData) < 64 {
		return 0, 0, 0, 0, fmt.Errorf("file too small for PE structure")
	}
	peHeaderOffset = int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	if peHeaderOffset < 0 || peHeaderOffset+24 >= int64(len(p.RawData)) {
		peHeaderOffset = findPESignature(p.RawData)
		if peHeaderOffset < 0 || peHeaderOffset+24 >= int64(len(p.RawData)) {
			return 0, 0, 0, 0, fmt.Errorf("invalid or missing PE header")
		}
	}
	optionalHeaderOffset = peHeaderOffset + 24
	if optionalHeaderOffset+40 >= int64(len(p.RawData)) {
		return 0, 0, 0, 0, fmt.Errorf("optional header too small")
	}
	fileAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+36 : optionalHeaderOffset+40])
	sectionAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+32 : optionalHeaderOffset+36])
	return fileAlignment, sectionAlignment, peHeaderOffset, optionalHeaderOffset, nil
}

func (p *PEFile) findNewSectionRVA(sectionAlignment uint32) uint32 {
	maxEnd := uint32(0)

	for _, section := range p.Sections {
		// Calcola la fine effettiva della sezione
		sectionEnd := section.RVA + section.VirtualSize

		// Allinea la fine al successivo boundary di sectionAlignment
		alignedEnd := (sectionEnd + sectionAlignment - 1) &^ (sectionAlignment - 1)

		// Mantieni il valore massimo
		if alignedEnd > maxEnd {
			maxEnd = alignedEnd
		}
	}

	if maxEnd == 0 {
		return sectionAlignment
	}

	return maxEnd
}

func (p *PEFile) extendRawDataIfNeeded(neededSize int64) {
	if neededSize > int64(len(p.RawData)) {
		p.RawData = append(p.RawData, make([]byte, neededSize-int64(len(p.RawData)))...)
	}
}

func (p *PEFile) updateSectionHeaders(peHeaderOffset int64, optionalHeaderSize uint16) error {
	sectionCount := uint16(len(p.Sections))
	if err := WriteAtOffset(p.RawData, peHeaderOffset+6, sectionCount); err != nil {
		return fmt.Errorf("unable to update section count: %w", err)
	}
	headerOffset := peHeaderOffset + 24 + int64(optionalHeaderSize)
	for i, section := range p.Sections {
		offset := headerOffset + int64(i*40)
		if err := p.writeSectionHeader(uint64(offset), section); err != nil {
			return fmt.Errorf("failed to write section header %d: %w", i, err)
		}
	}
	return nil
}

func (p *PEFile) writeSectionHeader(offset uint64, section Section) error {
	if offset+40 > uint64(len(p.RawData)) {
		return fmt.Errorf("offset %d out of bounds for section header", offset)
	}
	for i := range p.RawData[offset : offset+40] {
		p.RawData[offset+uint64(i)] = 0
	}
	nameBytes := []byte(section.Name)
	copy(p.RawData[offset:offset+8], nameBytes[:min(len(nameBytes), 8)])
	writeUint32 := func(value uint32, start uint64) {
		for i := 0; i < 4; i++ {
			p.RawData[start+uint64(i)] = byte(value >> (8 * i))
		}
	}
	writeUint32(section.VirtualSize, offset+8)
	writeUint32(section.VirtualAddress, offset+12)
	writeUint32(uint32(section.Size), offset+16)
	writeUint32(uint32(section.Offset), offset+20)
	writeUint32(section.Flags, offset+36)
	return nil
}

func (p *PEFile) updateSizeOfImage(sectionAlignment uint32, newSectionRVA, newSectionSize uint32) error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small for PE structure")
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	if peHeaderOffset < 0 || peHeaderOffset+24 >= int64(len(p.RawData)) {
		peHeaderOffset = findPESignature(p.RawData)
		if peHeaderOffset < 0 || peHeaderOffset+24 >= int64(len(p.RawData)) {
			return fmt.Errorf("invalid or missing PE header")
		}
	}
	optionalHeaderOffset := peHeaderOffset + 24
	if optionalHeaderOffset+2 >= int64(len(p.RawData)) {
		return fmt.Errorf("optional header offset out of bounds: %d", optionalHeaderOffset)
	}

	maxVirtualEnd := uint32(0)
	for _, section := range p.Sections {
		alignedVirtualSize := calculateAlignedSize(section.VirtualSize, sectionAlignment)
		virtualEnd := section.RVA + alignedVirtualSize
		if virtualEnd > maxVirtualEnd {
			maxVirtualEnd = virtualEnd
		}
	}
	newSectionEnd := newSectionRVA + calculateAlignedSize(newSectionSize, sectionAlignment)
	if newSectionEnd > maxVirtualEnd {
		maxVirtualEnd = newSectionEnd
	}
	maxVirtualEnd = (maxVirtualEnd + sectionAlignment - 1) &^ (sectionAlignment - 1)
	magic := binary.LittleEndian.Uint16(p.RawData[optionalHeaderOffset : optionalHeaderOffset+2])
	sizeOfImageOffset := optionalHeaderOffset + 52 // Offset predefinito per PE32
	if magic == 0x20b {                            // PE32+ (64-bit)
		sizeOfImageOffset = optionalHeaderOffset + 56
	}
	if sizeOfImageOffset+4 > int64(len(p.RawData)) {
		return fmt.Errorf("SizeOfImage offset out of bounds: %d (file size: %d)", sizeOfImageOffset, len(p.RawData))
	}
	return WriteAtOffset(p.RawData, sizeOfImageOffset, maxVirtualEnd)
}

func (p *PEFile) ensureSpaceForNewSectionHeader() error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small for PE structure")
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	if peHeaderOffset < 0 || peHeaderOffset+24 >= int64(len(p.RawData)) {
		return fmt.Errorf("invalid PE header offset: %d", peHeaderOffset)
	}
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+20 : peHeaderOffset+22])
	sectionHeaderOffset := peHeaderOffset + 24 + int64(optionalHeaderSize)
	newHeaderEnd := sectionHeaderOffset + int64(len(p.Sections)+1)*40
	minSectionOffset := int64(len(p.RawData))
	for _, section := range p.Sections {
		if section.Offset > 0 && section.Offset < minSectionOffset {
			minSectionOffset = section.Offset
		}
	}
	if newHeaderEnd <= minSectionOffset {
		return nil
	}
	return p.expandHeaderSpace(newHeaderEnd - minSectionOffset)
}

func (p *PEFile) expandHeaderSpace(spaceNeeded int64) error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small for PE structure")
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	if peHeaderOffset < 0 || peHeaderOffset+24 >= int64(len(p.RawData)) {
		return fmt.Errorf("invalid PE header offset: %d", peHeaderOffset)
	}

	optionalHeaderOffset := peHeaderOffset + 24
	if optionalHeaderOffset+40 >= int64(len(p.RawData)) {
		return fmt.Errorf("optional header too small for file alignment")
	}
	fileAlignment := binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+36 : optionalHeaderOffset+40])
	alignedSpaceNeeded := (spaceNeeded + int64(fileAlignment) - 1) &^ (int64(fileAlignment) - 1)
	var sectionsToMove []Section
	for i, section := range p.Sections {
		if section.Offset > 0 {
			p.Sections[i].Offset += alignedSpaceNeeded
			sectionsToMove = append(sectionsToMove, section)
		}
	}
	newFileSize := int64(len(p.RawData)) + alignedSpaceNeeded
	if newFileSize > int64(len(p.RawData)) {
		p.RawData = append(p.RawData, make([]byte, alignedSpaceNeeded)...)
	}
	for i := len(sectionsToMove) - 1; i >= 0; i-- {
		section := sectionsToMove[i]
		oldOffset := section.Offset - alignedSpaceNeeded
		copy(p.RawData[section.Offset:section.Offset+section.Size], p.RawData[oldOffset:oldOffset+section.Size])
		for j := oldOffset; j < oldOffset+section.Size; j++ {
			p.RawData[j] = 0
		}
	}
	return nil
}
