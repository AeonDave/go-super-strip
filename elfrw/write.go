package elfrw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"io"
	"os"
)

func (e *ELFFile) writeAtOffset(pos int, value interface{}) error {
	var size int
	switch value.(type) {
	case uint16:
		size = 2
	case uint32:
		size = 4
	case uint64:
		size = 8
	default:
		size = len(e.RawData) - pos
	}
	if pos < 0 || pos+size > len(e.RawData) {
		return fmt.Errorf("offset out of bounds: %d (size %d)", pos, size)
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, e.GetEndian(), value); err != nil {
		return fmt.Errorf("failed to write value: %w", err)
	}
	copy(e.RawData[pos:], buf.Bytes())
	return nil
}

// WriteAtOffset writes a value to rawData at a specific offset with the given endianness.
func WriteAtOffset(rawData []byte, offset int64, value interface{}, endian binary.ByteOrder) error {
	var size int
	switch v := value.(type) {
	case uint16:
		size = 2
		if int(offset)+size > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		endian.PutUint16(rawData[int(offset):int(offset)+size], v)
	case uint32:
		size = 4
		if int(offset)+size > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		endian.PutUint32(rawData[int(offset):int(offset)+size], v)
	case uint64:
		size = 8
		if int(offset)+size > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		endian.PutUint64(rawData[int(offset):int(offset)+size], v)
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

// Save writes RawData to the file with optional header updates and truncation
func (e *ELFFile) Save(updateHeaders bool, newSize int64) error {
	if e.File == nil {
		return fmt.Errorf("invalid file reference")
	}

	if newSize > 0 && int64(len(e.RawData)) > newSize {
		e.RawData = e.RawData[:newSize]
	}

	if updateHeaders {
		if err := e.updateHeadersAtomic(); err != nil {
			return err
		}
	}

	// Normal save process for ELF files
	if err := e.writeRawDataAtomic(); err != nil {
		return err
	}
	if err := e.truncateFileAtomic(); err != nil {
		return err
	}
	return nil
}

// updateHeadersAtomic updates all headers needed before saving
func (e *ELFFile) updateHeadersAtomic() error {
	if err := e.UpdateELFHeader(); err != nil {
		return fmt.Errorf("failed to update ELF header: %w", err)
	}
	return nil
}

// writeRawDataAtomic writes RawData to the file from the start
func (e *ELFFile) writeRawDataAtomic() error {
	if _, err := e.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to reposition file: %w", err)
	}
	if _, err := e.File.Write(e.RawData); err != nil {
		return fmt.Errorf("failed to write changes to disk: %w", err)
	}
	return nil
}

// truncateFileAtomic truncates the file to the length of RawData
func (e *ELFFile) truncateFileAtomic() error {
	if err := e.File.Truncate(int64(len(e.RawData))); err != nil {
		return fmt.Errorf("failed to resize file: %w", err)
	}
	return nil
}

// UpdateELFHeader updates the ELF header fields in RawData
func (e *ELFFile) UpdateELFHeader() error {
	if len(e.RawData) < 64 {
		return fmt.Errorf("file too small for ELF structure")
	}

	endian := e.GetEndian()

	// Update section count (e_shnum)
	numberOfSections := uint16(len(e.Sections))
	var shNumOffset int
	if e.Is64Bit {
		shNumOffset = 60
	} else {
		shNumOffset = 48
	}

	return WriteAtOffset(e.RawData, int64(shNumOffset), numberOfSections, endian)
}

func (e *ELFFile) updateProgramHeader(index uint16, newSize uint64) error {
	phdr, err := e.ELF.GetProgramHeader(index)
	if err != nil {
		return fmt.Errorf("failed to read program header %d: %w", index, err)
	}

	phdrOffset, phdrFileSize := phdr.GetFileOffset(), phdr.GetFileSize()
	phdrPos := e.getProgramHeaderPosition(index)

	if phdrOffset >= newSize {
		return e.writeProgramHeaderOffsets(phdrPos, newSize, 0)
	} else if phdrOffset+phdrFileSize > newSize {
		newFileSize := newSize - phdrOffset
		return e.writeProgramHeaderOffsets(phdrPos, phdrOffset, newFileSize)
	}
	return nil
}

func (e *ELFFile) getProgramHeaderPosition(index uint16) uint64 {
	if e.Is64Bit {
		phoff := e.readUint64(32)
		entsize := uint64(e.readUint16(54))
		return phoff + uint64(index)*entsize
	}
	// 32-bit ELF
	phoff32 := uint64(e.readUint32(28))
	entsize32 := uint64(e.readUint16(42))
	return phoff32 + uint64(index)*entsize32
}

func (e *ELFFile) writeProgramHeaderOffsets(pos, offset, size uint64) error {
	if e.Is64Bit {
		if err := e.writeAtOffset(int(pos+8), offset); err != nil {
			return err
		}
		return e.writeAtOffset(int(pos+32), size)
	}
	// 32-bit: p_offset at +4, p_filesz at +16
	if err := e.writeAtOffset(int(pos+4), uint32(offset)); err != nil {
		return err
	}
	return e.writeAtOffset(int(pos+16), uint32(size))
}

func (e *ELFFile) UpdateSectionHeaders() error {
	shoffPos, _, _ := e.getHeaderPositions() // Extract only the first value
	sectionHeaderOffset := e.getSectionHeaderOffset(shoffPos)
	if sectionHeaderOffset == 0 {
		return nil
	}

	var entrySize uint64
	if e.Is64Bit {
		entrySize = uint64(e.readUint16(58))
	} else {
		entrySize = uint64(e.readUint16(46))
	}
	for i, section := range e.Sections {
		pos := sectionHeaderOffset + uint64(i)*entrySize
		if err := e.writeAtOffset(int(pos+24), section.Offset); err != nil {
			return err
		}
		if err := e.writeAtOffset(int(pos+32), section.Size); err != nil {
			return err
		}
	}
	return nil
}

func (e *ELFFile) UpdateProgramHeaders() error {
	var phoff, entsize uint64
	if e.Is64Bit {
		phoff = e.readUint64(32)
		entsize = uint64(e.readUint16(54))
	} else {
		phoff = uint64(e.readUint32(28))
		entsize = uint64(e.readUint16(42))
	}
	for i, segment := range e.Segments {
		pos := phoff + uint64(i)*entsize
		if e.Is64Bit {
			if err := e.writeAtOffset(int(pos+8), segment.Offset); err != nil {
				return err
			}
			if err := e.writeAtOffset(int(pos+32), segment.FileSize); err != nil {
				return err
			}
		} else {
			if err := e.writeAtOffset(int(pos+4), uint32(segment.Offset)); err != nil {
				return err
			}
			if err := e.writeAtOffset(int(pos+16), uint32(segment.FileSize)); err != nil {
				return err
			}
		}
	}
	return nil
}

// AddSection adds a new section to the ELF file with content from the specified file
func (e *ELFFile) AddSection(sectionName string, contentFilePath string) error {
	// Read content from file
	content, err := os.ReadFile(contentFilePath)
	if err != nil {
		return fmt.Errorf("failed to read content file: %w", err)
	}

	// Validate that we can add sections
	if err := e.validateForSectionAddition(); err != nil {
		return fmt.Errorf("cannot add section: %w", err)
	}

	// Calculate alignment (typically 16 bytes for data sections)
	alignment := uint64(16)
	contentSize := uint64(len(content))
	alignedSize := (contentSize + alignment - 1) &^ (alignment - 1)

	// Find appropriate location for new section data
	newDataOffset := e.findSectionDataLocation()

	// Pad content to alignment
	paddedContent := make([]byte, alignedSize)
	copy(paddedContent, content)

	// Create new section metadata
	newSection := Section{
		Name:   sectionName,
		Offset: int64(newDataOffset),
		Size:   int64(contentSize),
		Type:   1, // SHT_PROGBITS
		Flags:  2, // SHF_ALLOC
		Index:  len(e.Sections),
	}

	// Update string table with new section name
	if err := e.addSectionNameToStringTable(sectionName); err != nil {
		return fmt.Errorf("failed to update string table: %w", err)
	}

	// Add section to list
	e.Sections = append(e.Sections, newSection)

	// Expand file to accommodate new data
	if newDataOffset+alignedSize > uint64(len(e.RawData)) {
		newSize := newDataOffset + alignedSize
		expandedData := make([]byte, newSize)
		copy(expandedData, e.RawData)
		e.RawData = expandedData
	}

	// Write section content
	copy(e.RawData[newDataOffset:newDataOffset+contentSize], content)
	// Update section headers in the file
	if err := e.rebuildSectionHeaders(); err != nil {
		return fmt.Errorf("failed to rebuild section headers: %w", err)
	}

	// Clear the name offsets cache
	e.clearNameOffsetCache()

	return nil
}

// validateForSectionAddition checks if we can safely add a section
func (e *ELFFile) validateForSectionAddition() error {
	if len(e.RawData) < 64 {
		return fmt.Errorf("file too small to be valid ELF")
	}

	// Check if we have section headers
	offsets := e.getELFOffsets()
	shoff := e.readValue(offsets.shOff, e.Is64Bit)
	shnum := e.readValue16(offsets.shNum)

	if shoff == 0 || shnum == 0 {
		return fmt.Errorf("file has no section headers - cannot add sections")
	}

	// Check if section header string table exists
	shstrndx := e.readValue16(offsets.shStrNdx)
	if shstrndx >= shnum {
		return fmt.Errorf("invalid section header string table index")
	}

	return nil
}

// findSectionDataLocation finds appropriate location for new section data
func (e *ELFFile) findSectionDataLocation() uint64 {
	// Find the end of the last section data
	maxEnd := uint64(0)
	for _, section := range e.Sections {
		if section.Type != 8 { // Skip SHT_NOBITS sections
			sectionEnd := section.Offset + section.Size
			if uint64(sectionEnd) > maxEnd {
				maxEnd = uint64(sectionEnd)
			}
		}
	}

	// Align to 16-byte boundary
	alignment := uint64(16)
	return (maxEnd + alignment - 1) &^ (alignment - 1)
}

// addSectionNameToStringTable adds a section name to .shstrtab
func (e *ELFFile) addSectionNameToStringTable(sectionName string) error {
	offsets := e.getELFOffsets()
	shstrndx := e.readValue16(offsets.shStrNdx)

	if int(shstrndx) >= len(e.Sections) {
		return fmt.Errorf("invalid section header string table index")
	}

	strtabSection := &e.Sections[shstrndx]
	if strtabSection.Offset == 0 {
		return fmt.Errorf("section header string table is empty")
	}

	// Check if section name already exists in current string table
	if strtabSection.Size > 0 {
		_, err := e.findStringInTable(sectionName, strtabSection)
		if err == nil {
			return nil // Already exists, no need to add
		}
	}

	// Rebuild the entire string table with all section names including the new one
	return e.rebuildStringTableWithNewName(sectionName, shstrndx)
}

// findStringInTable searches for a string in the given string table section
func (e *ELFFile) findStringInTable(searchName string, strtabSection *Section) (uint32, error) {
	if strtabSection.Size == 0 {
		return 0, fmt.Errorf("string table is empty")
	}

	// Handle empty string specially - it should always be at offset 0
	if searchName == "" {
		return 0, nil
	}

	stringTable := e.RawData[strtabSection.Offset : strtabSection.Offset+strtabSection.Size]
	nameBytes := []byte(searchName)

	for i := uint32(0); i < uint32(len(stringTable)); i++ {
		// Check if we have enough space for the string at this position
		if i+uint32(len(nameBytes)) > uint32(len(stringTable)) {
			continue
		}

		// Check if the string matches at this position
		if string(stringTable[i:i+uint32(len(nameBytes))]) == searchName {
			// Check if this is a proper string termination
			endPos := i + uint32(len(nameBytes))
			if endPos == uint32(len(stringTable)) || stringTable[endPos] == 0 {
				return i, nil
			}
		}
	}

	return 0, fmt.Errorf("string not found in table")
}

// rebuildStringTableWithNewName rebuilds the entire string table with all existing names plus a new one
func (e *ELFFile) rebuildStringTableWithNewName(newName string, shstrndx uint16) error {
	// Collect all existing section names
	nameSet := make(map[string]bool)
	for _, section := range e.Sections {
		if section.Name != "" {
			nameSet[section.Name] = true
		}
	}

	// Add the new section name
	nameSet[newName] = true

	// Build new string table
	var newTable []byte
	newTable = append(newTable, 0) // Start with null byte for empty names

	nameOffsets := make(map[string]uint32)
	nameOffsets[""] = 0 // Empty name at offset 0

	// Add all unique names to the string table
	for name := range nameSet {
		nameOffsets[name] = uint32(len(newTable))
		newTable = append(newTable, []byte(name)...)
		newTable = append(newTable, 0) // null terminator
	}

	// Find location for new string table at end of file
	newOffset := e.findSectionDataLocation()
	newTableSize := uint64(len(newTable))

	// Expand file if necessary
	if newOffset+newTableSize > uint64(len(e.RawData)) {
		newSize := newOffset + newTableSize
		expandedData := make([]byte, newSize)
		copy(expandedData, e.RawData)
		e.RawData = expandedData
	}

	// Write new string table
	copy(e.RawData[newOffset:newOffset+newTableSize], newTable)

	// Update string table section metadata
	strtabSection := &e.Sections[shstrndx]
	strtabSection.Offset = int64(newOffset)
	strtabSection.Size = int64(newTableSize)

	// Store the name offset mapping for quick lookup during section header writing
	e.nameOffsets = nameOffsets

	return nil
}

// rebuildSectionHeaders rebuilds the section header table
func (e *ELFFile) rebuildSectionHeaders() error {
	// Calculate section header entry size
	var shentsize uint64
	if e.Is64Bit {
		shentsize = 64 // 64-bit section header size
	} else {
		shentsize = 40 // 32-bit section header size
	}

	// Calculate total size needed for section headers
	totalHeaderSize := uint64(len(e.Sections)) * shentsize

	// Find location for section headers (at end of file)
	headerOffset := e.findSectionHeaderLocation()

	// Expand file if necessary
	if headerOffset+totalHeaderSize > uint64(len(e.RawData)) {
		newSize := headerOffset + totalHeaderSize
		expandedData := make([]byte, newSize)
		copy(expandedData, e.RawData)
		e.RawData = expandedData
	}

	// Write section headers
	for i, section := range e.Sections {
		headerPos := headerOffset + uint64(i)*shentsize
		if err := e.writeSectionHeader(section, headerPos); err != nil {
			return fmt.Errorf("failed to write section header %d: %w", i, err)
		}
	}

	// Update ELF header with new section info
	if err := e.updateELFHeaderSectionInfo(headerOffset, uint16(len(e.Sections))); err != nil {
		return fmt.Errorf("failed to update ELF header: %w", err)
	}

	return nil
}

// findSectionHeaderLocation finds appropriate location for section headers
func (e *ELFFile) findSectionHeaderLocation() uint64 {
	// Place section headers at the end of file, aligned to 8 bytes
	alignment := uint64(8)
	fileEnd := uint64(len(e.RawData))
	return (fileEnd + alignment - 1) &^ (alignment - 1)
}

// writeSectionHeader writes a single section header
func (e *ELFFile) writeSectionHeader(section Section, offset uint64) error {
	// Get string table offset for section name
	nameOffset, err := e.getSectionNameOffset(section.Name)
	if err != nil {
		return fmt.Errorf("failed to get name offset: %w", err)
	}

	endian := e.GetEndian()

	if e.Is64Bit {
		// 64-bit section header
		if offset+64 > uint64(len(e.RawData)) {
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
		// 32-bit section header
		if offset+40 > uint64(len(e.RawData)) {
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

// getSectionNameOffset finds the offset of a section name in .shstrtab
func (e *ELFFile) getSectionNameOffset(sectionName string) (uint32, error) {
	// Use cached name offsets if available (set during string table rebuilding)
	if e.nameOffsets != nil {
		if offset, exists := e.nameOffsets[sectionName]; exists {
			return offset, nil
		}
	}

	// Fallback to searching in the current string table
	offsets := e.getELFOffsets()
	shstrndx := e.readValue16(offsets.shStrNdx)

	if int(shstrndx) >= len(e.Sections) {
		return 0, fmt.Errorf("invalid string table index")
	}

	strtabSection := e.Sections[shstrndx]
	return e.findStringInTable(sectionName, &strtabSection)
}

// updateELFHeaderSectionInfo updates section-related fields in ELF header
func (e *ELFFile) updateELFHeaderSectionInfo(shoff uint64, shnum uint16) error {
	offsets := e.getELFOffsets()

	// Update e_shoff
	if err := e.writeValueAtOffset(offsets.shOff, shoff, e.Is64Bit); err != nil {
		return fmt.Errorf("failed to update e_shoff: %w", err)
	}

	// Update e_shnum
	if err := e.writeValue16AtOffset(offsets.shNum, shnum); err != nil {
		return fmt.Errorf("failed to update e_shnum: %w", err)
	}

	return nil
}

// Helper functions for writing values
func (e *ELFFile) writeValueAtOffset(offset int, value uint64, is64bit bool) error {
	endian := e.GetEndian()
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
	endian := e.GetEndian()
	endian.PutUint16(e.RawData[offset:offset+2], value)
	return nil
}

// clearNameOffsetCache clears the cached string table offsets
func (e *ELFFile) clearNameOffsetCache() {
	e.nameOffsets = nil
}

// AnalyzeELF provides detailed analysis of ELF file structure

// AddHexSection adds a new section to the ELF file with hex-encoded content from the specified file
// If password is provided, the hex data is encrypted with AES-256-GCM before storage
func (e *ELFFile) AddHexSection(sectionName string, contentFilePath string, password string) error {
	var finalContent []byte
	var encrypted bool
	var err error

	if password != "" {
		// Use common crypto functions for processing with password
		finalContent, err = common.ProcessFileForInsertion(contentFilePath, password)
		if err != nil {
			return fmt.Errorf("failed to process file with encryption: %w", err)
		}
		encrypted = true
	} else {
		// No password - just convert to hex
		finalContent, err = common.FileToHex(contentFilePath)
		if err != nil {
			return fmt.Errorf("failed to convert file to hex: %w", err)
		}
		encrypted = false
	}

	// Now proceed with the normal section addition logic using finalContent
	return e.addSectionWithContent(sectionName, finalContent, encrypted)
}

// addSectionWithContent adds a section with the provided raw content
func (e *ELFFile) addSectionWithContent(sectionName string, content []byte, encrypted bool) error {
	// Validate that we can add sections
	if err := e.validateForSectionAddition(); err != nil {
		return fmt.Errorf("cannot add section: %w", err)
	}

	// Calculate alignment (typically 16 bytes for data sections)
	alignment := uint64(16)
	contentSize := uint64(len(content))
	alignedSize := (contentSize + alignment - 1) &^ (alignment - 1)

	// Find appropriate location for new section data
	newDataOffset := e.findSectionDataLocation()

	// Pad content to alignment
	paddedContent := make([]byte, alignedSize)
	copy(paddedContent, content)

	// Create new section metadata
	newSection := Section{
		Name:   sectionName,
		Offset: int64(newDataOffset),
		Size:   int64(contentSize),
		Type:   1, // SHT_PROGBITS
		Flags:  2, // SHF_ALLOC
		Index:  len(e.Sections),
	}

	// Update string table with new section name
	if err := e.addSectionNameToStringTable(sectionName); err != nil {
		return fmt.Errorf("failed to update string table: %w", err)
	}

	// Add section to list
	e.Sections = append(e.Sections, newSection)

	// Rebuild section headers
	if err := e.rebuildSectionHeaders(); err != nil {
		return fmt.Errorf("failed to rebuild section headers: %w", err)
	}

	// Clear the name offsets cache
	e.clearNameOffsetCache()

	// Extend raw data if necessary and write new section data
	requiredSize := newDataOffset + alignedSize
	if requiredSize > uint64(len(e.RawData)) {
		newRawData := make([]byte, requiredSize)
		copy(newRawData, e.RawData)
		e.RawData = newRawData
	}

	// Write section content
	copy(e.RawData[newDataOffset:newDataOffset+contentSize], content)

	// Zero-fill padding
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

// Add fallback mode support for corrupted ELF files
type ELFFileMode struct {
	usedFallbackMode bool
}

// saveWithAppendOnly appends new data to the end of the file without rewriting the entire file
// This is used for corrupted/packed files to avoid damaging their structure
func (e *ELFFile) saveWithAppendOnly() error {
	// Read the current file to get its original size
	currentInfo, err := e.File.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}
	originalSize := currentInfo.Size()

	// Only append the new data that was added beyond the original file size
	if int64(len(e.RawData)) > originalSize {
		newData := e.RawData[originalSize:]

		// Seek to the end of the file
		if _, err := e.File.Seek(0, io.SeekEnd); err != nil {
			return fmt.Errorf("failed to seek to end of file: %w", err)
		}

		// Append only the new data
		if _, err := e.File.Write(newData); err != nil {
			return fmt.Errorf("failed to append new data: %w", err)
		}
	}

	return nil
}
