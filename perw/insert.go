package perw

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"os"
)

func (p *PEFile) AddHexSection(sectionName string, dataOrFile string, password string) error {
	fileStat, err := os.Stat(dataOrFile)
	isFile := err == nil && !fileStat.IsDir()

	var content []byte
	if isFile {
		content, err = common.ProcessFileForInsertion(dataOrFile, password)
		if err != nil {
			return fmt.Errorf("failed to process file for insertion: %w", err)
		}
	} else {
		content, err = common.ProcessStringForInsertion(dataOrFile, password)
		if err != nil {
			return fmt.Errorf("failed to process string for insertion: %w", err)
		}
	}
	return p.addSectionWithContent(sectionName, content, password != "")
}

func (p *PEFile) addSectionWithContent(sectionName string, content []byte, isEncrypted bool) error {
	if len(content) == 0 {
		return fmt.Errorf("content cannot be empty")
	}

	// Sanitize section name (max 8 chars, null-terminated)
	name := sanitizeSectionName(sectionName)

	// Check if section already exists
	for _, section := range p.Sections {
		if section.Name == name {
			return fmt.Errorf("section '%s' already exists", name)
		}
	}

	// Add section normally - even if PE was corrupted, we can fix it by rewriting headers
	return p.addSectionNormal(name, content)
}

// addSectionNormal adds a section to a properly structured PE file
func (p *PEFile) addSectionNormal(name string, content []byte) error {
	// Calculate PE structure offsets
	offsets, err := p.calculateOffsets()
	if err != nil {
		return fmt.Errorf("failed to calculate PE offsets: %w", err)
	}

	// Calculate new section properties
	newSection, err := p.calculateNewSectionProperties(name, content, offsets)
	if err != nil {
		return fmt.Errorf("failed to calculate section properties: %w", err)
	}

	// Expand RawData to accommodate new section
	newFileSize := newSection.Offset + newSection.Size
	if int64(len(p.RawData)) < newFileSize {
		// Expand the buffer
		newData := make([]byte, newFileSize)
		copy(newData, p.RawData)
		p.RawData = newData
	}

	// Write section content
	copy(p.RawData[newSection.Offset:newSection.Offset+newSection.Size], content)

	// Write section header
	if err := p.writeSectionHeader(newSection, offsets); err != nil {
		return fmt.Errorf("failed to write section header: %w", err)
	}

	// Update number of sections in COFF header
	if err := p.updateNumberOfSections(len(p.Sections) + 1); err != nil {
		return fmt.Errorf("failed to update section count: %w", err)
	}

	// Update optional header fields
	if err := p.updateOptionalHeaderForNewSection(newSection); err != nil {
		return fmt.Errorf("failed to update optional header: %w", err)
	}

	// Add section to our internal list
	p.Sections = append(p.Sections, *newSection)

	return nil
}

// sanitizeSectionName ensures section name is valid for PE format
func sanitizeSectionName(name string) string {
	// PE section names are max 8 bytes, null-terminated
	if len(name) > 8 {
		name = name[:8]
	}

	// Ensure it contains only valid characters
	sanitized := ""
	for _, char := range name {
		if (char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '.' {
			sanitized += string(char)
		}
	}

	if sanitized == "" {
		sanitized = ".data"
	}

	return sanitized
}

// calculateNewSectionProperties calculates properties for the new section
func (p *PEFile) calculateNewSectionProperties(name string, content []byte, offsets *PEOffsets) (*Section, error) {
	// Determine file alignment (default 512 bytes)
	fileAlignment := uint32(512)
	sectionAlignment := uint32(4096) // Default section alignment in memory

	// If we have PE headers, try to read actual alignment values
	if p.PE != nil && p.PE.OptionalHeader != nil {
		switch oh := p.PE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			fileAlignment = oh.FileAlignment
			sectionAlignment = oh.SectionAlignment
		case *pe.OptionalHeader64:
			fileAlignment = oh.FileAlignment
			sectionAlignment = oh.SectionAlignment
		}
	}

	// Calculate file offset (aligned)
	var fileOffset int64
	if len(p.Sections) > 0 {
		// Place after last section
		lastSection := p.Sections[len(p.Sections)-1]
		fileOffset = common.AlignUp64(lastSection.Offset+lastSection.Size, int64(fileAlignment))
	} else {
		// Place after headers
		fileOffset = common.AlignUp64(int64(p.sizeOfHeaders), int64(fileAlignment))
	}

	// Calculate virtual address (aligned)
	var virtualAddress uint32
	if len(p.Sections) > 0 {
		// Place after last section in memory
		lastSection := p.Sections[len(p.Sections)-1]
		lastVirtualEnd := lastSection.VirtualAddress + common.AlignUp(lastSection.VirtualSize, sectionAlignment)
		virtualAddress = common.AlignUp(lastVirtualEnd, sectionAlignment)
	} else {
		// Place after headers in memory
		virtualAddress = common.AlignUp(p.sizeOfHeaders, sectionAlignment)
	}

	// Calculate size (aligned for file)
	rawSize := common.AlignUp64(int64(len(content)), int64(fileAlignment))
	virtualSize := uint32(len(content))

	// Set section characteristics (readable, writable, contains initialized data)
	characteristics := uint32(0x40000000 | 0x80000000 | 0x00000040) // READ | WRITE | INITIALIZED_DATA

	section := &Section{
		Name:           name,
		Offset:         fileOffset,
		Size:           rawSize,
		VirtualAddress: virtualAddress,
		VirtualSize:    virtualSize,
		Index:          len(p.Sections),
		Flags:          characteristics,
		RVA:            virtualAddress,
		FileOffset:     uint32(fileOffset),
		IsExecutable:   false,
		IsReadable:     true,
		IsWritable:     true,
	}

	return section, nil
}

// writeSectionHeader writes the section header to the PE file
func (p *PEFile) writeSectionHeader(section *Section, offsets *PEOffsets) error {
	headerOffset := offsets.FirstSectionHdr + int64(section.Index)*40

	// Ensure we have enough space in RawData
	if int(headerOffset+40) > len(p.RawData) {
		return fmt.Errorf("section header would exceed file bounds")
	}

	header := p.RawData[headerOffset : headerOffset+40]

	// Clear header
	for i := range header {
		header[i] = 0
	}

	// Write section name (8 bytes)
	nameBytes := []byte(section.Name)
	if len(nameBytes) > 8 {
		nameBytes = nameBytes[:8]
	}
	copy(header[0:8], nameBytes)

	// Write section fields
	binary.LittleEndian.PutUint32(header[8:12], section.VirtualSize)     // VirtualSize
	binary.LittleEndian.PutUint32(header[12:16], section.VirtualAddress) // VirtualAddress
	binary.LittleEndian.PutUint32(header[16:20], uint32(section.Size))   // SizeOfRawData
	binary.LittleEndian.PutUint32(header[20:24], uint32(section.Offset)) // PointerToRawData
	binary.LittleEndian.PutUint32(header[24:28], 0)                      // PointerToRelocations
	binary.LittleEndian.PutUint32(header[28:32], 0)                      // PointerToLinenumbers
	binary.LittleEndian.PutUint16(header[32:34], 0)                      // NumberOfRelocations
	binary.LittleEndian.PutUint16(header[34:36], 0)                      // NumberOfLinenumbers
	binary.LittleEndian.PutUint32(header[36:40], section.Flags)          // Characteristics

	return nil
}

// updateOptionalHeaderForNewSection updates SizeOfImage in optional header
func (p *PEFile) updateOptionalHeaderForNewSection(newSection *Section) error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small for PE headers")
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + 20

	// Check if we have optional header
	if int(coffHeaderOffset+18) > len(p.RawData) {
		return fmt.Errorf("cannot read optional header size")
	}

	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[coffHeaderOffset+16 : coffHeaderOffset+18])
	if optionalHeaderSize == 0 {
		return nil // No optional header
	}

	// Read magic to determine PE32 vs PE32+
	if int(optionalHeaderOffset+2) > len(p.RawData) {
		return fmt.Errorf("cannot read optional header magic")
	}

	magic := binary.LittleEndian.Uint16(p.RawData[optionalHeaderOffset : optionalHeaderOffset+2])

	// Calculate new SizeOfImage (should be aligned to section alignment)
	sectionAlignment := uint32(4096) // Default
	var sizeOfImageOffset int64

	switch magic {
	case 0x10b: // PE32
		if int(optionalHeaderOffset+96) > len(p.RawData) {
			return fmt.Errorf("PE32 optional header too small")
		}
		sectionAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+32 : optionalHeaderOffset+36])
		sizeOfImageOffset = optionalHeaderOffset + 56
	case 0x20b: // PE32+
		if int(optionalHeaderOffset+112) > len(p.RawData) {
			return fmt.Errorf("PE32+ optional header too small")
		}
		sectionAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+32 : optionalHeaderOffset+36])
		sizeOfImageOffset = optionalHeaderOffset + 56
	default:
		return fmt.Errorf("unknown optional header magic: 0x%x", magic)
	}
	newSizeOfImage := common.AlignUp(newSection.VirtualAddress+newSection.VirtualSize, sectionAlignment)
	binary.LittleEndian.PutUint32(p.RawData[sizeOfImageOffset:sizeOfImageOffset+4], newSizeOfImage)
	p.sizeOfImage = newSizeOfImage
	return nil
}
