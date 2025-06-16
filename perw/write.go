package perw

import (
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"io"
)

// WriteAtOffset writes a value to rawData at a specific offset, ensuring bounds and endianness.
func WriteAtOffset(rawData []byte, offset int64, value interface{}) error {
	size := 0
	switch v := value.(type) {
	case uint32:
		size = 4
		if int(offset)+size > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		binary.LittleEndian.PutUint32(rawData[int(offset):int(offset)+size], v)
	case uint64:
		size = 8
		if int(offset)+size > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		binary.LittleEndian.PutUint64(rawData[int(offset):int(offset)+size], v)
	case uint16:
		size = 2
		if int(offset)+size > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		binary.LittleEndian.PutUint16(rawData[int(offset):int(offset)+size], v)
	case uint8:
		if int(offset) >= len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		rawData[int(offset)] = v
	case []byte:
		size = len(v)
		if int(offset)+size > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		copy(rawData[int(offset):int(offset)+size], v)
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}
	return nil
}

// CommitChanges writes RawData to the file and truncates it if needed.
func (p *PEFile) CommitChanges(newSize int64) error {
	if p.File == nil {
		return fmt.Errorf("invalid file reference")
	}

	if newSize > 0 && int64(len(p.RawData)) > newSize {
		p.RawData = p.RawData[:newSize]
	}

	if err := p.UpdateCOFFHeader(); err != nil {
		return fmt.Errorf("failed to update COFF header: %w", err)
	}
	// Skip UpdateOptionalHeader since it's been removed - it was causing corruption
	// Updated fields should be handled individually where needed

	if _, err := p.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to reposition file: %w", err)
	}
	if _, err := p.File.Write(p.RawData); err != nil {
		return fmt.Errorf("failed to write changes to disk: %w", err)
	}
	if err := p.File.Truncate(int64(len(p.RawData))); err != nil {
		return fmt.Errorf("failed to resize file: %w", err)
	}
	return nil
}

// CommitChangesSimple writes RawData to the file without updating headers
func (p *PEFile) CommitChangesSimple(newSize int64) error {
	if p.File == nil {
		return fmt.Errorf("invalid file reference")
	}

	if newSize > 0 && int64(len(p.RawData)) > newSize {
		p.RawData = p.RawData[:newSize]
	}

	if _, err := p.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to reposition file: %w", err)
	}
	if _, err := p.File.Write(p.RawData); err != nil {
		return fmt.Errorf("failed to write changes to disk: %w", err)
	}
	if err := p.File.Truncate(int64(len(p.RawData))); err != nil {
		return fmt.Errorf("failed to resize file: %w", err)
	}
	return nil
}

// UpdateCOFFHeader updates the COFF header fields in RawData.
func (p *PEFile) UpdateCOFFHeader() error {
	if p.PE == nil {
		return fmt.Errorf("PE structure not available")
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	coffHeaderOffset := peHeaderOffset + 4

	numberOfSections := uint16(len(p.Sections))
	return WriteAtOffset(p.RawData, coffHeaderOffset+2, numberOfSections)
}

// AddHexSection adds a new section to the PE file with hex-encoded content from the specified file
// If password is provided, the hex data is encrypted with AES-256-GCM before storage
func (p *PEFile) AddHexSection(sectionName string, contentFilePath string, password string) error {
	// Use common crypto functions
	finalContent, err := common.ProcessFileForInsertion(contentFilePath, password)
	if err != nil {
		return fmt.Errorf("failed to process file for insertion: %w", err)
	}

	// Now proceed with the normal section addition logic using finalContent
	return p.addSectionWithContent(sectionName, finalContent, password != "")
}

// addSectionWithContent adds a section with the provided raw content
func (p *PEFile) addSectionWithContent(sectionName string, content []byte, encrypted bool) error {
	// Ensure we have space for the new section header
	if err := p.ensureSpaceForNewSectionHeader(); err != nil {
		return fmt.Errorf("failed to ensure space for section header: %w", err)
	}

	// Get alignments from PE headers
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	optionalHeaderOffset := peHeaderOffset + 4 + 20

	// Read file and section alignment (these are in the same positions for 32/64 bit)
	fileAlignment := binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+36 : optionalHeaderOffset+40])
	sectionAlignment := binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+32 : optionalHeaderOffset+36])

	// Calculate aligned content size
	rawDataSize := uint32(len(content))
	alignedSize := (rawDataSize + fileAlignment - 1) &^ (fileAlignment - 1)

	// Find the end of the file to place our new section
	fileSize := int64(len(p.RawData))
	newOffset := (fileSize + int64(fileAlignment) - 1) &^ (int64(fileAlignment) - 1)

	// Calculate virtual address for new section
	var newVirtualAddress uint32
	if len(p.Sections) > 0 {
		// Find the section with the highest RVA + VirtualSize
		maxVirtualEnd := uint32(0)
		for _, section := range p.Sections {
			virtualEnd := section.RVA + ((section.VirtualSize + sectionAlignment - 1) &^ (sectionAlignment - 1))
			if virtualEnd > maxVirtualEnd {
				maxVirtualEnd = virtualEnd
			}
		}
		newVirtualAddress = maxVirtualEnd
	} else {
		newVirtualAddress = sectionAlignment
	}

	// Extend RawData to fit the new section
	neededSize := newOffset + int64(alignedSize)
	if neededSize > int64(len(p.RawData)) {
		newRawData := make([]byte, neededSize)
		copy(newRawData, p.RawData)
		p.RawData = newRawData
	}

	// Copy content to the new section location and zero-pad
	copy(p.RawData[newOffset:newOffset+int64(len(content))], content)
	for i := newOffset + int64(len(content)); i < newOffset+int64(alignedSize); i++ {
		p.RawData[i] = 0
	}

	// Create new section
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

	// Add section to list
	p.Sections = append(p.Sections, newSection)

	// Update section count in COFF header
	newSectionCount := uint16(len(p.Sections))
	if err := WriteAtOffset(p.RawData, peHeaderOffset+6, newSectionCount); err != nil {
		return fmt.Errorf("failed to update section count: %w", err)
	}
	// Write the new section header
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+20 : peHeaderOffset+22])
	sectionHeaderOffset := peHeaderOffset + 4 + 20 + int64(optionalHeaderSize)
	newHeaderOffset := sectionHeaderOffset + int64((newSection.Index)*40)

	if err := p.writeSectionHeader(uint64(newHeaderOffset), newSection); err != nil {
		return fmt.Errorf("failed to write section header: %w", err)
	}

	// Update SizeOfImage in Optional Header with corrected offsets
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
