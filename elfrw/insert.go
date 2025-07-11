package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
)

func (e *ELFFile) AddSection(sectionName string, dataOrFile string, password string) *common.OperationResult {
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

	err = e.addSectionWithContent(sectionName, content, password != "")
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to insert section: %v", err))
	}

	message := fmt.Sprintf("Added hex section '%s'", sectionName)
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

func (e *ELFFile) addSectionWithContent(sectionName string, content []byte, encrypted bool) error {
	if err := e.validateForSectionAddition(); err != nil {
		return fmt.Errorf("cannot add section: %w", err)
	}
	alignment := uint64(16)
	contentSize := uint64(len(content))
	alignedSize := (contentSize + alignment - 1) &^ (alignment - 1)
	newDataOffset := e.findSectionDataLocation()
	paddedContent := make([]byte, alignedSize)
	copy(paddedContent, content)
	newSection := Section{
		Name:   sectionName,
		Offset: int64(newDataOffset),
		Size:   int64(contentSize),
		Type:   SHT_PROGBITS, // SHT_PROGBITS
		Flags:  SHF_ALLOC,    // SHF_ALLOC
		Index:  len(e.Sections),
	}
	if err := e.addSectionNameToStringTable(sectionName); err != nil {
		return fmt.Errorf("failed to update string table: %w", err)
	}
	e.Sections = append(e.Sections, newSection)
	if err := e.rebuildSectionHeaders(); err != nil {
		return fmt.Errorf("failed to rebuild section headers: %w", err)
	}
	e.clearNameOffsetCache()
	requiredSize := newDataOffset + alignedSize
	if requiredSize > uint64(len(e.RawData)) {
		newRawData := make([]byte, requiredSize)
		copy(newRawData, e.RawData)
		e.RawData = newRawData
	}

	copy(e.RawData[newDataOffset:newDataOffset+contentSize], content)
	for i := newDataOffset + contentSize; i < newDataOffset+alignedSize; i++ {
		e.RawData[i] = 0
	}

	fmt.Printf("Hex section '%s' added successfully", sectionName)
	if encrypted {
		fmt.Printf(" (encrypted)")
	}
	fmt.Printf("\n")
	return nil
}

func (e *ELFFile) validateForSectionAddition() error {
	if len(e.RawData) < 64 {
		return fmt.Errorf("file too small to be valid ELF")
	}
	var shoff uint64
	var shnum uint16
	var shstrndx uint16

	if e.Is64Bit {
		shoff = e.readValue(ELF64_E_SHOFF, e.Is64Bit)
		shnum = e.readValue16(ELF64_E_SHNUM)
		shstrndx = e.readValue16(ELF64_E_SHSTRNDX)
	} else {
		shoff = e.readValue(ELF32_E_SHOFF, e.Is64Bit)
		shnum = e.readValue16(ELF32_E_SHNUM)
		shstrndx = e.readValue16(ELF32_E_SHSTRNDX)
	}
	if shoff == 0 || shnum == 0 {
		return fmt.Errorf("file has no section headers - cannot add sections")
	}
	if shstrndx >= shnum {
		return fmt.Errorf("invalid section header string table index")
	}

	return nil
}

func (e *ELFFile) findSectionDataLocation() uint64 {
	maxEnd := uint64(0)
	for _, section := range e.Sections {
		if section.Type != SHT_NOBITS { // Skip SHT_NOBITS sections
			sectionEnd := section.Offset + section.Size
			if uint64(sectionEnd) > maxEnd {
				maxEnd = uint64(sectionEnd)
			}
		}
	}
	alignment := uint64(16)
	return (maxEnd + alignment - 1) &^ (alignment - 1)
}

func (e *ELFFile) addSectionNameToStringTable(sectionName string) error {
	var shstrndx uint16
	if e.Is64Bit {
		shstrndx = e.readValue16(ELF64_E_SHSTRNDX)
	} else {
		shstrndx = e.readValue16(ELF32_E_SHSTRNDX)
	}
	if int(shstrndx) >= len(e.Sections) {
		return fmt.Errorf("invalid section header string table index")
	}
	strtabSection := &e.Sections[shstrndx]
	if strtabSection.Offset == 0 {
		return fmt.Errorf("section header string table is empty")
	}
	if strtabSection.Size > 0 {
		_, err := e.findStringInTable(sectionName, strtabSection)
		if err == nil {
			return nil // Already exists, no need to add
		}
	}
	return e.rebuildStringTableWithNewName(sectionName)
}

func (e *ELFFile) findStringInTable(searchName string, strtabSection *Section) (uint32, error) {
	if strtabSection.Size == 0 {
		return 0, fmt.Errorf("string table is empty")
	}
	if searchName == "" {
		return 0, nil
	}

	stringTable := e.RawData[strtabSection.Offset : strtabSection.Offset+strtabSection.Size]
	nameBytes := []byte(searchName)

	for i := uint32(0); i < uint32(len(stringTable)); i++ {
		if i+uint32(len(nameBytes)) > uint32(len(stringTable)) {
			continue
		}
		if string(stringTable[i:i+uint32(len(nameBytes))]) == searchName {
			endPos := i + uint32(len(nameBytes))
			if endPos == uint32(len(stringTable)) || stringTable[endPos] == 0 {
				return i, nil
			}
		}
	}

	return 0, fmt.Errorf("string not found in table")
}

func (e *ELFFile) rebuildStringTableWithNewName(newName string) error {
	nameSet := make(map[string]bool)
	for _, section := range e.Sections {
		if section.Name != "" {
			nameSet[section.Name] = true
		}
	}
	nameSet[newName] = true
	var newTable []byte
	newTable = append(newTable, 0) // Start with null byte for empty names
	nameOffsets := make(map[string]uint32)
	nameOffsets[""] = 0 // Empty name at offset 0

	for name := range nameSet {
		nameOffsets[name] = uint32(len(newTable))
		newTable = append(newTable, []byte(name)...)
		newTable = append(newTable, 0) // null terminator
	}
	e.nameOffsets = nameOffsets
	return nil
}

func (e *ELFFile) rebuildSectionHeaders() error {
	var shstrndx uint16
	if e.Is64Bit {
		shstrndx = e.readValue16(ELF64_E_SHSTRNDX)
	} else {
		shstrndx = e.readValue16(ELF32_E_SHSTRNDX)
	}

	if int(shstrndx) >= len(e.Sections) {
		return fmt.Errorf("invalid section header string table index")
	}
	strtabSection := &e.Sections[shstrndx]

	nameSet := make(map[string]bool)
	for _, section := range e.Sections {
		if section.Name != "" {
			nameSet[section.Name] = true
		}
	}

	var newTable []byte
	newTable = append(newTable, 0) // Start with null byte
	nameOffsets := make(map[string]uint32)
	nameOffsets[""] = 0

	for name := range nameSet {
		if _, exists := nameOffsets[name]; !exists {
			nameOffsets[name] = uint32(len(newTable))
			newTable = append(newTable, []byte(name)...)
			newTable = append(newTable, 0)
		}
	}
	e.nameOffsets = nameOffsets
	newOffset := e.findSectionDataLocation()
	newTableSize := uint64(len(newTable))
	requiredSize := newOffset + newTableSize
	if requiredSize > uint64(len(e.RawData)) {
		newRawData := make([]byte, requiredSize)
		copy(newRawData, e.RawData)
		e.RawData = newRawData
	}

	copy(e.RawData[newOffset:newOffset+newTableSize], newTable)

	strtabSection.Offset = int64(newOffset)
	strtabSection.Size = int64(newTableSize)

	var shentsize uint64
	if e.Is64Bit {
		shentsize = ELF64_SHDR_SIZE
	} else {
		shentsize = ELF32_SHDR_SIZE
	}

	totalHeaderSize := uint64(len(e.Sections)) * shentsize
	headerOffset := e.findSectionHeaderLocation()
	if headerOffset+totalHeaderSize > uint64(len(e.RawData)) {
		newSize := headerOffset + totalHeaderSize
		expandedData := make([]byte, newSize)
		copy(expandedData, e.RawData)
		e.RawData = expandedData
	}
	for i, section := range e.Sections {
		headerPos := headerOffset + uint64(i)*shentsize
		if err := e.writeSectionHeader(section, headerPos); err != nil {
			return fmt.Errorf("failed to write section header %d: %w", i, err)
		}
	}
	if err := e.updateELFHeaderSectionInfo(headerOffset, uint16(len(e.Sections))); err != nil {
		return fmt.Errorf("failed to update ELF header: %w", err)
	}

	return nil
}

func (e *ELFFile) findSectionHeaderLocation() uint64 {
	alignment := uint64(8)
	fileEnd := uint64(len(e.RawData))
	return (fileEnd + alignment - 1) &^ (alignment - 1)
}

func (e *ELFFile) writeSectionHeader(section Section, offset uint64) error {
	nameOffset, err := e.getSectionNameOffset(section.Name)
	if err != nil {
		return fmt.Errorf("failed to get name offset: %w", err)
	}

	endian := e.getEndian()

	if e.Is64Bit {
		if offset+ELF64_SHDR_SIZE > uint64(len(e.RawData)) {
			return fmt.Errorf("section header would exceed file bounds")
		}

		endian.PutUint32(e.RawData[offset:offset+4], nameOffset)                 // sh_name
		endian.PutUint32(e.RawData[offset+4:offset+8], section.Type)             // sh_type
		endian.PutUint64(e.RawData[offset+8:offset+16], section.Flags)           // sh_flags
		endian.PutUint64(e.RawData[offset+16:offset+24], 0)                      // sh_addr
		endian.PutUint64(e.RawData[offset+24:offset+32], uint64(section.Offset)) // sh_offset
		endian.PutUint64(e.RawData[offset+32:offset+40], uint64(section.Size))   // sh_size
		endian.PutUint32(e.RawData[offset+40:offset+44], 0)                      // sh_link
		endian.PutUint32(e.RawData[offset+44:offset+48], 0)                      // sh_info
		endian.PutUint64(e.RawData[offset+48:offset+56], 1)                      // sh_addralign
		endian.PutUint64(e.RawData[offset+56:offset+64], 0)                      // sh_entsize
	} else {
		if offset+ELF32_SHDR_SIZE > uint64(len(e.RawData)) {
			return fmt.Errorf("section header would exceed file bounds")
		}

		endian.PutUint32(e.RawData[offset:offset+4], nameOffset)                 // sh_name
		endian.PutUint32(e.RawData[offset+4:offset+8], section.Type)             // sh_type
		endian.PutUint32(e.RawData[offset+8:offset+12], uint32(section.Flags))   // sh_flags
		endian.PutUint32(e.RawData[offset+12:offset+16], 0)                      // sh_addr
		endian.PutUint32(e.RawData[offset+16:offset+20], uint32(section.Offset)) // sh_offset
		endian.PutUint32(e.RawData[offset+20:offset+24], uint32(section.Size))   // sh_size
		endian.PutUint32(e.RawData[offset+24:offset+28], 0)                      // sh_link
		endian.PutUint32(e.RawData[offset+28:offset+32], 0)                      // sh_info
		endian.PutUint32(e.RawData[offset+32:offset+36], 1)                      // sh_addralign
		endian.PutUint32(e.RawData[offset+36:offset+40], 0)                      // sh_entsize
	}

	return nil
}

func (e *ELFFile) getSectionNameOffset(sectionName string) (uint32, error) {
	if e.nameOffsets != nil {
		if offset, exists := e.nameOffsets[sectionName]; exists {
			return offset, nil
		}
	}
	var shstrndx uint16
	if e.Is64Bit {
		shstrndx = e.readValue16(ELF64_E_SHSTRNDX)
	} else {
		shstrndx = e.readValue16(ELF32_E_SHSTRNDX)
	}

	if int(shstrndx) >= len(e.Sections) {
		return 0, fmt.Errorf("invalid string table index")
	}
	strtabSection := e.Sections[shstrndx]
	return e.findStringInTable(sectionName, &strtabSection)
}

func (e *ELFFile) updateELFHeaderSectionInfo(shoff uint64, shnum uint16) error {
	var shoffOffset, shnumOffset int

	if e.Is64Bit {
		shoffOffset = ELF64_E_SHOFF
		shnumOffset = ELF64_E_SHNUM
	} else {
		shoffOffset = ELF32_E_SHOFF
		shnumOffset = ELF32_E_SHNUM
	}
	if err := e.writeValueAtOffset(shoffOffset, shoff, e.Is64Bit); err != nil {
		return fmt.Errorf("failed to update e_shoff: %w", err)
	}
	if err := e.writeValue16AtOffset(shnumOffset, shnum); err != nil {
		return fmt.Errorf("failed to update e_shnum: %w", err)
	}
	return nil
}

func (e *ELFFile) writeValueAtOffset(offset int, value uint64, is64bit bool) error {
	endian := e.getEndian()
	if is64bit {
		if offset+8 > len(e.RawData) {
			return fmt.Errorf("write would exceed file bounds")
		}
		endian.PutUint64(e.RawData[offset:offset+8], value)
	} else {
		if offset+4 > len(e.RawData) {
			return fmt.Errorf("write would exceed file bounds")
		}
		endian.PutUint32(e.RawData[offset:offset+4], uint32(value))
	}
	return nil
}

func (e *ELFFile) writeValue16AtOffset(offset int, value uint16) error {
	if offset+2 > len(e.RawData) {
		return fmt.Errorf("write would exceed file bounds")
	}
	endian := e.getEndian()
	endian.PutUint16(e.RawData[offset:offset+2], value)
	return nil
}
