package perw

import (
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"io"
)

// WriteAtOffset writes a value to rawData at a specific offset, ensuring bounds and endianness.
// WriteAtOffset: scrive un valore in rawData a un offset specifico (endianness little)
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

// Save writes RawData to the file with optional header updates and truncation
// Save: salva RawData su file, aggiorna header e tronca se richiesto
func (p *PEFile) Save(updateHeaders bool, newSize int64) error {
	if p.File == nil {
		return fmt.Errorf("invalid file reference")
	}

	if newSize > 0 && int64(len(p.RawData)) > newSize {
		p.RawData = p.RawData[:newSize]
	}

	if updateHeaders {
		if err := p.updateHeadersAtomic(); err != nil {
			return err
		}
	}

	if err := p.writeRawDataAtomic(); err != nil {
		return err
	}
	if err := p.truncateFileAtomic(); err != nil {
		return err
	}
	return nil
}

// updateHeadersAtomic updates all headers needed before saving
// updateHeadersAtomic: aggiorna tutti gli header necessari prima del salvataggio
func (p *PEFile) updateHeadersAtomic() error {
	if err := p.UpdateCOFFHeader(); err != nil {
		return fmt.Errorf("failed to update COFF header: %w", err)
	}
	// UpdateOptionalHeader intentionally skipped (see comment in Save)
	return nil
}

// writeRawDataAtomic writes RawData to the file from the start
// writeRawDataAtomic: scrive RawData su file dall'inizio
func (p *PEFile) writeRawDataAtomic() error {
	if _, err := p.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to reposition file: %w", err)
	}
	if _, err := p.File.Write(p.RawData); err != nil {
		return fmt.Errorf("failed to write changes to disk: %w", err)
	}
	return nil
}

// truncateFileAtomic truncates the file to the length of RawData
// truncateFileAtomic: tronca il file alla lunghezza di RawData
func (p *PEFile) truncateFileAtomic() error {
	if err := p.File.Truncate(int64(len(p.RawData))); err != nil {
		return fmt.Errorf("failed to resize file: %w", err)
	}
	return nil
}

// UpdateCOFFHeader updates the COFF header fields in RawData.
// UpdateCOFFHeader: aggiorna il numero di sezioni nel COFF header
func (p *PEFile) UpdateCOFFHeader() error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small for PE structure")
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	coffHeaderOffset := peHeaderOffset + 4

	numberOfSections := uint16(len(p.Sections))
	return WriteAtOffset(p.RawData, coffHeaderOffset+2, numberOfSections)
}

// AddHexSection adds a new section to the PE file with hex-encoded content from the specified file
// AddHexSection: aggiunge una sezione hex (opzionalmente cifrata) al PE
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
// addSectionWithContent: aggiunge una sezione con contenuto raw
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

// --- Atomic helpers for addSectionWithContent ---
// --- Helper atomici per addSectionWithContent ---
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

func calculateAlignedSize(size, alignment uint32) uint32 {
	return (size + alignment - 1) &^ (alignment - 1)
}

func findNewSectionOffset(fileSize int64, fileAlignment uint32) int64 {
	return (fileSize + int64(fileAlignment) - 1) &^ (int64(fileAlignment) - 1)
}

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

func (p *PEFile) extendRawDataIfNeeded(neededSize int64) {
	if neededSize > int64(len(p.RawData)) {
		newRawData := make([]byte, neededSize)
		copy(newRawData, p.RawData)
		p.RawData = newRawData
	}
}

func writeSectionContent(rawData []byte, newOffset int64, content []byte, alignedSize uint32) {
	copy(rawData[newOffset:newOffset+int64(len(content))], content)
	for i := newOffset + int64(len(content)); i < newOffset+int64(alignedSize); i++ {
		rawData[i] = 0
	}
}

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
// writeSectionHeader: scrive un header di sezione all'offset specificato
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
// updateSizeOfImage: aggiorna il campo SizeOfImage nell'Optional Header
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
// ensureSpaceForNewSectionHeader: verifica che ci sia spazio per un nuovo section header
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
