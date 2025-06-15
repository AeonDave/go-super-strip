package perw

import (
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"io"
	"os"
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
	if err := p.UpdateOptionalHeader(); err != nil {
		return fmt.Errorf("failed to update optional header: %w", err)
	}
	if err := p.UpdateSectionHeaders(); err != nil {
		return fmt.Errorf("failed to update section headers: %w", err)
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

// UpdateSectionHeaders updates the COFF section header table in RawData.
func (p *PEFile) UpdateSectionHeaders() error {
	if p.PE == nil {
		return fmt.Errorf("PE structure not available")
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+20 : peHeaderOffset+22])
	sectionHeaderOffset := peHeaderOffset + 4 + 20 + int64(optionalHeaderSize)

	for i, section := range p.Sections {
		headerOffset := sectionHeaderOffset + int64(i*40)

		if int(headerOffset)+40 > len(p.RawData) {
			return fmt.Errorf("section header %d out of bounds", i)
		}

		name := make([]byte, 8)
		copy(name, section.Name)
		if err := WriteAtOffset(p.RawData, headerOffset, name); err != nil {
			return fmt.Errorf("failed to update name for section %d: %w", i, err)
		} // Safe type conversions with overflow checks
		if section.Size > 0xFFFFFFFF {
			return fmt.Errorf("section %d size too large for PE format: %d", i, section.Size)
		}
		if section.Offset > 0xFFFFFFFF {
			return fmt.Errorf("section %d offset too large for PE format: %d", i, section.Offset)
		}

		sectionSize := uint32(section.Size)
		sectionOffset := uint32(section.Offset)

		if err := WriteAtOffset(p.RawData, headerOffset+8, sectionSize); err != nil {
			return fmt.Errorf("failed to update virtual size for section %d: %w", i, err)
		}
		if err := WriteAtOffset(p.RawData, headerOffset+12, section.RVA); err != nil {
			return fmt.Errorf("failed to update virtual address for section %d: %w", i, err)
		}
		if err := WriteAtOffset(p.RawData, headerOffset+16, sectionSize); err != nil {
			return fmt.Errorf("failed to update raw data size for section %d: %w", i, err)
		}
		if err := WriteAtOffset(p.RawData, headerOffset+20, sectionOffset); err != nil {
			return fmt.Errorf("failed to update raw data pointer for section %d: %w", i, err)
		}
		if err := WriteAtOffset(p.RawData, headerOffset+36, section.Flags); err != nil {
			return fmt.Errorf("failed to update characteristics for section %d: %w", i, err)
		}
	}
	return nil
}

// UpdateOptionalHeader updates the optional header fields in RawData.
func (p *PEFile) UpdateOptionalHeader() error {
	if p.PE == nil {
		return fmt.Errorf("PE structure not available")
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	optionalHeaderOffset := peHeaderOffset + 4 + 20

	var sizeOfImage uint32
	for _, section := range p.Sections {
		sectionEnd := section.RVA + uint32(section.Size)
		if sectionEnd > sizeOfImage {
			sizeOfImage = sectionEnd
		}
	}

	sectionAlignment := uint32(0x1000)
	if len(p.RawData) >= int(optionalHeaderOffset)+32 {
		sectionAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+32 : optionalHeaderOffset+36])
	}
	sizeOfImage = (sizeOfImage + sectionAlignment - 1) &^ (sectionAlignment - 1)

	sizeOfHeaders := uint32(p.Sections[0].Offset)

	if p.Is64Bit {
		if err := WriteAtOffset(p.RawData, optionalHeaderOffset+56, sizeOfImage); err != nil {
			return fmt.Errorf("failed to update SizeOfImage: %w", err)
		}
		if err := WriteAtOffset(p.RawData, optionalHeaderOffset+60, sizeOfHeaders); err != nil {
			return fmt.Errorf("failed to update SizeOfHeaders: %w", err)
		}
	} else {
		if err := WriteAtOffset(p.RawData, optionalHeaderOffset+56, sizeOfImage); err != nil {
			return fmt.Errorf("failed to update SizeOfImage: %w", err)
		}
		if err := WriteAtOffset(p.RawData, optionalHeaderOffset+60, sizeOfHeaders); err != nil {
			return fmt.Errorf("failed to update SizeOfHeaders: %w", err)
		}
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

// AddSection adds a new section to the PE file with content from the specified file
func (p *PEFile) AddSection(sectionName string, contentFilePath string) error {
	// Read content from file
	content, err := os.ReadFile(contentFilePath)
	if err != nil {
		return fmt.Errorf("failed to read content file: %w", err)
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

	if err := p.writeSectionHeader(&newSection, newHeaderOffset); err != nil {
		return fmt.Errorf("failed to write section header: %w", err)
	}

	// Update SizeOfImage in Optional Header
	if err := p.updateSizeOfImage(sectionAlignment); err != nil {
		return fmt.Errorf("failed to update SizeOfImage: %w", err)
	}

	fmt.Printf("Section '%s' added successfully\n", sectionName)
	return nil
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

	if err := p.writeSectionHeader(&newSection, newHeaderOffset); err != nil {
		return fmt.Errorf("failed to write section header: %w", err)
	}

	// Update SizeOfImage in Optional Header
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

	// SizeOfImage is at offset 56 in both 32-bit and 64-bit Optional Headers
	return WriteAtOffset(p.RawData, optionalHeaderOffset+56, maxVirtualEnd)
}

// writeSectionHeader writes a section header at the specified offset
func (p *PEFile) writeSectionHeader(section *Section, headerOffset int64) error {
	// Write section header fields
	name := make([]byte, 8)
	copy(name, section.Name)
	if err := WriteAtOffset(p.RawData, headerOffset, name); err != nil {
		return err
	}

	if err := WriteAtOffset(p.RawData, headerOffset+8, uint32(section.VirtualSize)); err != nil {
		return err
	}
	if err := WriteAtOffset(p.RawData, headerOffset+12, section.RVA); err != nil {
		return err
	}
	if err := WriteAtOffset(p.RawData, headerOffset+16, uint32(section.Size)); err != nil {
		return err
	}
	if err := WriteAtOffset(p.RawData, headerOffset+20, uint32(section.Offset)); err != nil {
		return err
	}
	// Skip relocations and line numbers (offset 24-32)
	if err := WriteAtOffset(p.RawData, headerOffset+24, uint32(0)); err != nil {
		return err
	}
	if err := WriteAtOffset(p.RawData, headerOffset+28, uint32(0)); err != nil {
		return err
	}
	if err := WriteAtOffset(p.RawData, headerOffset+32, uint16(0)); err != nil {
		return err
	}
	if err := WriteAtOffset(p.RawData, headerOffset+34, uint16(0)); err != nil {
		return err
	}
	// Write characteristics
	if err := WriteAtOffset(p.RawData, headerOffset+36, section.Flags); err != nil {
		return err
	}

	return nil
}
