package perw

import (
	"encoding/binary"
	"fmt"
	"gosstrip/common"
)

// AddHexSection adds a new section to the PE file with hex-encoded content from the specified file
func (p *PEFile) AddHexSection(sectionName string, contentFilePath string, password string) error {
	// Use common crypto functions
	finalContent, err := common.ProcessFileForInsertion(contentFilePath, password)
	if err != nil {
		return fmt.Errorf("failed to process file for insertion: %w", err)
	}

	// Now proceed with the normal section addition logic using finalContent
	return p.addSectionWithContent(sectionName, finalContent, password != "")
}

// AddHexSectionFromString adds a new section to the PE file with hex-encoded content from a string
func (p *PEFile) AddHexSectionFromString(sectionName string, data string, password string) error {
	// Use common crypto functions for string processing
	finalContent, err := common.ProcessStringForInsertion(data, password)
	if err != nil {
		return fmt.Errorf("failed to process string for insertion: %w", err)
	}

	// Now proceed with the normal section addition logic using finalContent
	return p.addSectionWithContent(sectionName, finalContent, password != "")
}

// addSectionWithContent adds a section with the provided raw content
func (p *PEFile) addSectionWithContent(sectionName string, content []byte, encrypted bool) error {
	// Step 1: Ensure space for new section header
	if err := p.ensureSpaceForNewSectionHeader(); err != nil {
		return fmt.Errorf("failed to ensure space for section header: %w", err)
	}

	// Step 2: Get alignments
	fileAlignment, sectionAlignment, peHeaderOffset, _, err := p.getPEAlignments()
	if err != nil {
		return err
	}

	// Step 3: Calculate aligned size
	rawDataSize := uint32(len(content))
	alignedSize := calculateAlignedSize(rawDataSize, fileAlignment)

	// Step 4: Find new section offset and RVA
	newOffset := findNewSectionOffset(int64(len(p.RawData)), fileAlignment)
	newVirtualAddress := findNewSectionRVA(p.Sections, sectionAlignment)

	// Step 5: Extend RawData if needed
	neededSize := newOffset + int64(alignedSize)
	p.extendRawDataIfNeeded(neededSize)

	// Step 6: Write section content and zero-pad
	writeSectionContent(p.RawData, newOffset, content, alignedSize)

	// Step 7: Create new section struct
	newSection := Section{
		Name:           sectionName,
		Offset:         newOffset,
		Size:           int64(alignedSize),
		VirtualAddress: newVirtualAddress,
		VirtualSize:    rawDataSize,
		Index:          len(p.Sections),
		Flags:          0x40000040, // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
		RVA:            newVirtualAddress,
	}
	p.Sections = append(p.Sections, newSection)

	// Step 8: Update section headers and SizeOfImage
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+20 : peHeaderOffset+22])
	if err := p.updateSectionHeaders(newSection, peHeaderOffset, optionalHeaderSize); err != nil {
		return err
	}
	if err := p.updateSizeOfImage(sectionAlignment); err != nil {
		return fmt.Errorf("failed to update SizeOfImage: %w", err)
	}

	fmt.Printf("Hex section '%s' added successfully", sectionName)
	if encrypted {
		fmt.Printf(" (encrypted)")
	}
	fmt.Printf("\n")
	return nil
}

// --- Helper functions for section insertion ---

// getPEAlignments extracts alignment values from PE headers
func (p *PEFile) getPEAlignments() (fileAlignment, sectionAlignment uint32, peHeaderOffset, optionalHeaderOffset int64, err error) {
	if len(p.RawData) < 64 {
		return 0, 0, 0, 0, fmt.Errorf("file too small for PE structure")
	}
	peHeaderOffset = int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	optionalHeaderOffset = peHeaderOffset + 4 + 20
	fileAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+36 : optionalHeaderOffset+40])
	sectionAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+32 : optionalHeaderOffset+36])
	return fileAlignment, sectionAlignment, peHeaderOffset, optionalHeaderOffset, nil
}

// calculateAlignedSize calculates the aligned size based on alignment requirements
func calculateAlignedSize(size, alignment uint32) uint32 {
	return (size + alignment - 1) &^ (alignment - 1)
}

// findNewSectionOffset finds the offset for a new section based on file alignment
func findNewSectionOffset(fileSize int64, fileAlignment uint32) int64 {
	return (fileSize + int64(fileAlignment) - 1) &^ (int64(fileAlignment) - 1)
}

// findNewSectionRVA finds the RVA for a new section based on existing sections
func findNewSectionRVA(sections []Section, sectionAlignment uint32) uint32 {
	if len(sections) > 0 {
		maxVirtualEnd := uint32(0)
		for _, section := range sections {
			virtualEnd := section.RVA + ((section.VirtualSize + sectionAlignment - 1) &^ (sectionAlignment - 1))
			if virtualEnd > maxVirtualEnd {
				maxVirtualEnd = virtualEnd
			}
		}
		return maxVirtualEnd
	}
	return sectionAlignment
}

// extendRawDataIfNeeded extends the RawData buffer if needed
func (p *PEFile) extendRawDataIfNeeded(neededSize int64) {
	if neededSize > int64(len(p.RawData)) {
		newRawData := make([]byte, neededSize)
		copy(newRawData, p.RawData)
		p.RawData = newRawData
	}
}

// writeSectionContent writes section content and pads with zeros
func writeSectionContent(rawData []byte, newOffset int64, content []byte, alignedSize uint32) {
	copy(rawData[newOffset:newOffset+int64(len(content))], content)
	for i := newOffset + int64(len(content)); i < newOffset+int64(alignedSize); i++ {
		rawData[i] = 0
	}
}

// updateSectionHeaders updates section count and writes the new section header
func (p *PEFile) updateSectionHeaders(newSection Section, peHeaderOffset int64, optionalHeaderSize uint16) error {
	// Update section count in COFF header
	newSectionCount := uint16(len(p.Sections))
	if err := WriteAtOffset(p.RawData, peHeaderOffset+6, newSectionCount); err != nil {
		return fmt.Errorf("failed to update section count: %w", err)
	}
	// Write the new section header
	sectionHeaderOffset := peHeaderOffset + 4 + 20 + int64(optionalHeaderSize)
	newHeaderOffset := sectionHeaderOffset + int64((newSection.Index)*40)
	if err := p.writeSectionHeader(uint64(newHeaderOffset), newSection); err != nil {
		return fmt.Errorf("failed to write section header: %w", err)
	}
	return nil
}

// writeSectionHeader writes a section header to the specified offset
func (p *PEFile) writeSectionHeader(offset uint64, section Section) error {
	if offset+40 > uint64(len(p.RawData)) {
		return fmt.Errorf("offset %d out of bounds for section header", offset)
	}

	// Clear the section header area
	for i := uint64(0); i < 40; i++ {
		p.RawData[offset+i] = 0
	}

	// Write Name (8 bytes)
	nameBytes := []byte(section.Name)
	if len(nameBytes) > 8 {
		nameBytes = nameBytes[:8]
	}
	copy(p.RawData[offset:offset+8], nameBytes)

	// Write VirtualSize (4 bytes at offset 8)
	virtualSize := uint32(section.VirtualSize)
	p.RawData[offset+8] = byte(virtualSize)
	p.RawData[offset+9] = byte(virtualSize >> 8)
	p.RawData[offset+10] = byte(virtualSize >> 16)
	p.RawData[offset+11] = byte(virtualSize >> 24)

	// Write VirtualAddress (4 bytes at offset 12)
	virtualAddr := uint32(section.VirtualAddress)
	p.RawData[offset+12] = byte(virtualAddr)
	p.RawData[offset+13] = byte(virtualAddr >> 8)
	p.RawData[offset+14] = byte(virtualAddr >> 16)
	p.RawData[offset+15] = byte(virtualAddr >> 24)

	// Write SizeOfRawData (4 bytes at offset 16)
	rawSize := uint32(section.Size)
	p.RawData[offset+16] = byte(rawSize)
	p.RawData[offset+17] = byte(rawSize >> 8)
	p.RawData[offset+18] = byte(rawSize >> 16)
	p.RawData[offset+19] = byte(rawSize >> 24)

	// Write PointerToRawData (4 bytes at offset 20)
	rawPtr := uint32(section.Offset)
	p.RawData[offset+20] = byte(rawPtr)
	p.RawData[offset+21] = byte(rawPtr >> 8)
	p.RawData[offset+22] = byte(rawPtr >> 16)
	p.RawData[offset+23] = byte(rawPtr >> 24)

	// Write Characteristics (4 bytes at offset 36)
	characteristics := uint32(section.Flags)
	p.RawData[offset+36] = byte(characteristics)
	p.RawData[offset+37] = byte(characteristics >> 8)
	p.RawData[offset+38] = byte(characteristics >> 16)
	p.RawData[offset+39] = byte(characteristics >> 24)

	return nil
}

// updateSizeOfImage updates the SizeOfImage field in the Optional Header
func (p *PEFile) updateSizeOfImage(sectionAlignment uint32) error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	optionalHeaderOffset := peHeaderOffset + 4 + 20

	// Find the highest virtual address + virtual size
	var maxVirtualEnd uint32
	for _, section := range p.Sections {
		virtualEnd := section.RVA + ((section.VirtualSize + sectionAlignment - 1) &^ (sectionAlignment - 1))
		if virtualEnd > maxVirtualEnd {
			maxVirtualEnd = virtualEnd
		}
	}

	// Check Optional Header Magic to determine PE32 vs PE32+
	magic := binary.LittleEndian.Uint16(p.RawData[optionalHeaderOffset : optionalHeaderOffset+2])
	var sizeOfImageOffset int64
	if magic == 0x20b { // PE32+ (64-bit)
		sizeOfImageOffset = 56 // Corrected from 60 to 56
	} else { // PE32 (32-bit)
		sizeOfImageOffset = 52 // Corrected from 56 to 52
	}

	return WriteAtOffset(p.RawData, optionalHeaderOffset+sizeOfImageOffset, maxVirtualEnd)
}

// ensureSpaceForNewSectionHeader ensures there's space for a new section header
func (p *PEFile) ensureSpaceForNewSectionHeader() error {
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+20 : peHeaderOffset+22])
	sectionHeaderOffset := peHeaderOffset + 4 + 20 + int64(optionalHeaderSize)
	currentSectionCount := len(p.Sections)

	// Calculate where the new section header would go
	newHeaderOffset := sectionHeaderOffset + int64(currentSectionCount*40)
	newHeaderEnd := newHeaderOffset + 40 // Each section header is 40 bytes

	// Find the first section's file offset to see how much space we have
	minSectionOffset := int64(len(p.RawData))
	for _, section := range p.Sections {
		if section.Offset > 0 && section.Offset < minSectionOffset {
			minSectionOffset = section.Offset
		}
	}

	// Check if we have enough space
	if newHeaderEnd <= minSectionOffset {
		// We have enough space, no need to do anything
		return nil
	}

	// No space available
	return fmt.Errorf("insufficient space for new section header (need %d bytes, have %d)",
		newHeaderEnd-minSectionOffset, minSectionOffset-newHeaderOffset)
}
