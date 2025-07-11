package perw

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"os"
)

func (p *PEFile) AddSection(sectionName string, dataOrFile string, password string) *common.OperationResult {
	fileStat, err := os.Stat(dataOrFile)
	isFile := err == nil && !fileStat.IsDir()

	var content []byte
	if isFile {
		content, err = common.ProcessFileForInsertion(dataOrFile, password)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("Failed to process file for insertion: %v", err))
		}
	} else {
		content, err = common.ProcessStringForInsertion(dataOrFile, password)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("Failed to process string for insertion: %v", err))
		}
	}

	err = p.addSectionWithContent(sectionName, content)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to insert section: %v", err))
	}

	message := fmt.Sprintf("Added hex section '%s'", sectionName)
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

func (p *PEFile) addSectionWithContent(sectionName string, content []byte) error {
	if len(content) == 0 {
		return fmt.Errorf("content cannot be empty")
	}
	name := common.SanitizeSectionName(sectionName)
	for _, section := range p.Sections {
		if section.Name == name {
			return fmt.Errorf("section '%s' already exists", name)
		}
	}
	return p.addSectionNormal(name, content)
}

func (p *PEFile) addSectionNormal(name string, content []byte) error {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return fmt.Errorf("failed to calculate PE offsets: %w", err)
	}
	newSection, err := p.calculateNewSectionProperties(name, content)
	if err != nil {
		return fmt.Errorf("failed to calculate section properties: %w", err)
	}
	newFileSize := newSection.Offset + newSection.Size
	if int64(len(p.RawData)) < newFileSize {
		newData := make([]byte, newFileSize)
		copy(newData, p.RawData)
		p.RawData = newData
	}

	copy(p.RawData[newSection.Offset:newSection.Offset+newSection.Size], content)
	if err := p.writeSectionHeader(newSection, offsets); err != nil {
		return fmt.Errorf("failed to write section header: %w", err)
	}
	if err := p.updateNumberOfSections(len(p.Sections) + 1); err != nil {
		return fmt.Errorf("failed to update section count: %w", err)
	}
	if err := p.updateOptionalHeaderForNewSection(newSection); err != nil {
		return fmt.Errorf("failed to update optional header: %w", err)
	}
	p.Sections = append(p.Sections, *newSection)
	return nil
}

func (p *PEFile) calculateNewSectionProperties(name string, content []byte) (*Section, error) {
	fileAlignment := uint32(PE_FILE_ALIGNMENT_MIN)
	sectionAlignment := uint32(PE_SECTION_ALIGNMENT_DEFAULT)
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

	section := Section{
		Name:           name,
		Offset:         fileOffset,
		Size:           rawSize,
		VirtualAddress: virtualAddress,
		VirtualSize:    virtualSize,
		Index:          len(p.Sections),
		Flags:          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
		RVA:            virtualAddress,
		FileOffset:     uint32(fileOffset),
		CommonSectionInfo: common.CommonSectionInfo{
			IsExecutable: false,
			IsReadable:   true,
			IsWritable:   true,
		},
	}

	return &section, nil
}

func (p *PEFile) writeSectionHeader(section *Section, offsets *PEOffsets) error {
	headerOffset := offsets.FirstSectionHdr + int64(section.Index)*PE_SECTION_HEADER_SIZE
	if int(headerOffset+PE_SECTION_HEADER_SIZE) > len(p.RawData) {
		return fmt.Errorf("section header would exceed file bounds")
	}
	header := p.RawData[headerOffset : headerOffset+PE_SECTION_HEADER_SIZE]
	for i := range header {
		header[i] = 0
	}
	nameBytes := []byte(section.Name)
	if len(nameBytes) > PE_SECTION_NAME_SIZE {
		nameBytes = nameBytes[:PE_SECTION_NAME_SIZE]
	}
	copy(header[0:PE_SECTION_NAME_SIZE], nameBytes)
	binary.LittleEndian.PutUint32(header[PE_SECTION_VIRTUAL_SIZE:PE_SECTION_VIRTUAL_SIZE+4], section.VirtualSize)    // VirtualSize
	binary.LittleEndian.PutUint32(header[PE_SECTION_VIRTUAL_ADDR:PE_SECTION_VIRTUAL_ADDR+4], section.VirtualAddress) // VirtualAddress
	binary.LittleEndian.PutUint32(header[PE_SECTION_RAW_SIZE:PE_SECTION_RAW_SIZE+4], uint32(section.Size))           // SizeOfRawData
	binary.LittleEndian.PutUint32(header[PE_SECTION_RAW_OFFSET:PE_SECTION_RAW_OFFSET+4], uint32(section.Offset))     // PointerToRawData
	binary.LittleEndian.PutUint32(header[PE_SECTION_RELOC_OFFSET:PE_SECTION_RELOC_OFFSET+4], 0)                      // PointerToRelocations
	binary.LittleEndian.PutUint32(header[PE_SECTION_LINENUMBER_OFFSET:PE_SECTION_LINENUMBER_OFFSET+4], 0)            // PointerToLinenumbers
	binary.LittleEndian.PutUint16(header[PE_SECTION_RELOC_COUNT:PE_SECTION_RELOC_COUNT+2], 0)                        // NumberOfRelocations
	binary.LittleEndian.PutUint16(header[PE_SECTION_LINENUMBER_COUNT:PE_SECTION_LINENUMBER_COUNT+2], 0)              // NumberOfLinenumbers
	binary.LittleEndian.PutUint32(header[PE_SECTION_CHARACTERISTICS:PE_SECTION_CHARACTERISTICS+4], section.Flags)    // Characteristics
	return nil
}

func (p *PEFile) updateOptionalHeaderForNewSection(newSection *Section) error {
	if len(p.RawData) < PE_DOS_HEADER_SIZE {
		return fmt.Errorf("file too small for PE headers")
	}
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
	coffHeaderOffset := peHeaderOffset + 4
	optionalHeaderOffset := coffHeaderOffset + PE_FILE_HEADER_SIZE
	if int(coffHeaderOffset+PE_OPTSIZE_OFFSET+2) > len(p.RawData) {
		return fmt.Errorf("cannot read optional header size")
	}
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[coffHeaderOffset+PE_OPTSIZE_OFFSET : coffHeaderOffset+PE_OPTSIZE_OFFSET+2])
	if optionalHeaderSize == 0 {
		return nil // No optional header
	}
	if int(optionalHeaderOffset+2) > len(p.RawData) {
		return fmt.Errorf("cannot read optional header magic")
	}
	magic := binary.LittleEndian.Uint16(p.RawData[optionalHeaderOffset : optionalHeaderOffset+2])
	sectionAlignment := uint32(PE_SECTION_ALIGNMENT_DEFAULT) // Default
	var sizeOfImageOffset int64
	switch magic {
	case PE32_MAGIC: // PE32
		if int(optionalHeaderOffset+PE32_DATA_DIRECTORIES) > len(p.RawData) {
			return fmt.Errorf("PE32 optional header too small")
		}
		sectionAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+PE32_SECTION_ALIGN : optionalHeaderOffset+PE32_SECTION_ALIGN+4])
		sizeOfImageOffset = optionalHeaderOffset + PE32_SIZE_OF_IMAGE
	case PE64_MAGIC: // PE32+
		if int(optionalHeaderOffset+PE64_DATA_DIRECTORIES) > len(p.RawData) {
			return fmt.Errorf("PE32+ optional header too small")
		}
		sectionAlignment = binary.LittleEndian.Uint32(p.RawData[optionalHeaderOffset+PE64_SECTION_ALIGN : optionalHeaderOffset+PE64_SECTION_ALIGN+4])
		sizeOfImageOffset = optionalHeaderOffset + PE64_SIZE_OF_IMAGE
	default:
		return fmt.Errorf("unknown optional header magic: 0x%x", magic)
	}
	newSizeOfImage := common.AlignUp(newSection.VirtualAddress+newSection.VirtualSize, sectionAlignment)
	binary.LittleEndian.PutUint32(p.RawData[sizeOfImageOffset:sizeOfImageOffset+4], newSizeOfImage)
	p.sizeOfImage = newSizeOfImage
	return nil
}
