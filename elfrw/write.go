package elfrw

import (
	"encoding/binary"
	"fmt"
	"io"
)

func WriteAtOffset(rawData []byte, offset int64, value interface{}, endian binary.ByteOrder) error {
	if offset < 0 {
		return fmt.Errorf("offset out of range: %d", offset)
	}
	var size int
	switch v := value.(type) {
	case int64:
		size = 8
		if int(offset)+size > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		endian.PutUint64(rawData[int(offset):int(offset)+size], uint64(v))
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
		size = 1
		if int(offset)+size > len(rawData) {
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

func (e *ELFFile) Save(updateHeaders bool, newSize int64) error {
	if e.File == nil {
		return fmt.Errorf("invalid file reference")
	}
	if newSize > 0 && int64(len(e.RawData)) > newSize {
		e.RawData = e.RawData[:newSize]
	}
	if e.usedFallbackMode {
		if _, err := e.File.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("failed to reposition file: %w", err)
		}
		if _, err := e.File.Write(e.RawData); err != nil {
			return fmt.Errorf("failed to write changes to disk: %w", err)
		}
		return nil
	}
	if updateHeaders {
		if err := e.modifyHeaders(uint64(len(e.RawData))); err != nil {
			fmt.Printf("⚠️ Warning: Failed to update headers: %v\n", err)
		}
	}
	if err := e.writeRawData(); err != nil {
		return err
	}
	if err := e.truncateFile(); err != nil {
		fmt.Printf("⚠️ Warning: Failed to truncate file: %v\n", err)
	}
	return nil
}

func (e *ELFFile) getProgramHeaderPosition(index uint16) (uint64, error) {
	// Ensure we have enough data to read the header
	minSize := ELF64_E_PHENTSIZE + 2
	if len(e.RawData) < minSize {
		return 0, fmt.Errorf("file too small to read program header info")
	}

	if e.Is64Bit {
		// Check if we have enough data to read a 64-bit offset
		if len(e.RawData) < ELF64_E_PHOFF+8 {
			return 0, fmt.Errorf("file too small to read 64-bit program header offset")
		}
		phOffset := e.readUint64(ELF64_E_PHOFF)

		// Validate the program header offset
		if phOffset == 0 || phOffset >= uint64(len(e.RawData)) {
			return 0, fmt.Errorf("invalid program header offset: %d", phOffset)
		}

		entrySize := uint64(e.readUint16(ELF64_E_PHENTSIZE))
		if entrySize == 0 {
			return 0, fmt.Errorf("invalid program header entry size: 0")
		}

		// Check for potential overflow
		if phOffset > uint64(len(e.RawData)) || uint64(index) > (uint64(len(e.RawData))-phOffset)/entrySize {
			return 0, fmt.Errorf("program header index out of range: %d", index)
		}

		return phOffset + uint64(index)*entrySize, nil
	}

	// 32-bit ELF
	if len(e.RawData) < ELF32_E_PHOFF+4 {
		return 0, fmt.Errorf("file too small to read 32-bit program header offset")
	}

	offset := uint64(e.readUint32(ELF32_E_PHOFF))
	if offset == 0 || offset >= uint64(len(e.RawData)) {
		return 0, fmt.Errorf("invalid program header offset: %d", offset)
	}

	entrySize := uint64(e.readUint16(ELF32_E_PHENTSIZE))
	if entrySize == 0 {
		return 0, fmt.Errorf("invalid program header entry size: 0")
	}

	// Check for potential overflow
	if offset > uint64(len(e.RawData)) || uint64(index) > (uint64(len(e.RawData))-offset)/entrySize {
		return 0, fmt.Errorf("program header index out of range: %d", index)
	}

	return offset + uint64(index)*entrySize, nil
}

func (e *ELFFile) writeAtOffset(pos int, value interface{}) error {
	return WriteAtOffset(e.RawData, int64(pos), value, e.getEndian())
}

func (e *ELFFile) writeValue(offset, value uint64, is64bit bool) error {
	// Add bounds checking to prevent panics
	if offset >= uint64(len(e.RawData)) {
		return fmt.Errorf("offset out of range: %d", offset)
	}

	if is64bit {
		if offset+8 > uint64(len(e.RawData)) {
			return fmt.Errorf("offset+size out of range: %d+8", offset)
		}
		return WriteAtOffset(e.RawData, int64(offset), value, e.getEndian())
	}

	if offset+4 > uint64(len(e.RawData)) {
		return fmt.Errorf("offset+size out of range: %d+4", offset)
	}
	return WriteAtOffset(e.RawData, int64(offset), uint32(value), e.getEndian())
}

func (e *ELFFile) writeRawData() error {
	if _, err := e.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to reposition file: %w", err)
	}
	if _, err := e.File.Write(e.RawData); err != nil {
		return fmt.Errorf("failed to write changes to disk: %w", err)
	}
	return nil
}

func (e *ELFFile) writeProgramHeaderOffsets(pos, offset, size uint64) error {
	if e.Is64Bit {
		if err := e.writeAtOffset(int(pos+ELF64_P_OFFSET), offset); err != nil {
			return err
		}
		return e.writeAtOffset(int(pos+ELF64_P_FILESZ), size)
	}
	if err := e.writeAtOffset(int(pos+ELF32_P_OFFSET), uint32(offset)); err != nil {
		return err
	}
	return e.writeAtOffset(int(pos+ELF32_P_FILESZ), uint32(size))
}

func (e *ELFFile) truncateFile() error {
	if err := e.File.Truncate(int64(len(e.RawData))); err != nil {
		return fmt.Errorf("failed to resize file: %w", err)
	}
	return nil
}

func (e *ELFFile) updateProgramHeader(index uint16, newSize uint64) error {
	header, err := e.ELF.GetProgramHeader(index)
	if err != nil {
		return fmt.Errorf("failed to read program header %d: %w", index, err)
	}
	headerOffset, headerSize := header.GetFileOffset(), header.GetFileSize()

	pos, err := e.getProgramHeaderPosition(index)
	if err != nil {
		// If we can't get the position, just skip this header
		return nil
	}

	if headerOffset >= newSize {
		return e.writeProgramHeaderOffsets(pos, newSize, 0)
	} else if headerOffset+headerSize > newSize {
		newFileSize := newSize - headerOffset
		return e.writeProgramHeaderOffsets(pos, headerOffset, newFileSize)
	}
	return nil
}

func (e *ELFFile) updateSectionHeaders() error {
	shoffPos, _, _ := e.getHeaderPositions()

	// Ensure we have enough data to read the section header offset
	if shoffPos < 0 || (e.Is64Bit && shoffPos+8 > len(e.RawData)) || (!e.Is64Bit && shoffPos+4 > len(e.RawData)) {
		// If we can't read the section header offset, just skip updating section headers
		return nil
	}

	sectionHeaderOffset, err := e.getSectionHeaderOffset(shoffPos)
	if err != nil {
		// If we can't get the section header offset, just skip updating section headers
		return nil
	}

	if sectionHeaderOffset == 0 {
		return nil
	}

	// Ensure we have enough data to read the section header entry size
	entrySize := uint64(0)
	if e.Is64Bit {
		if ELF64_E_SHENTSIZE+2 > len(e.RawData) {
			return nil
		}
		entrySize = uint64(e.readUint16(ELF64_E_SHENTSIZE))
	} else {
		if ELF32_E_SHENTSIZE+2 > len(e.RawData) {
			return nil
		}
		entrySize = uint64(e.readUint16(ELF32_E_SHENTSIZE))
	}

	if entrySize == 0 {
		return nil
	}

	for i, section := range e.Sections {
		pos := sectionHeaderOffset + uint64(i)*entrySize

		// Ensure the position is within the file
		if pos >= uint64(len(e.RawData)) {
			continue
		}

		if e.Is64Bit {
			// Ensure we have enough data to write the offset and size
			if int(pos+ELF64_S_OFFSET+8) > len(e.RawData) || int(pos+ELF64_S_SIZE+8) > len(e.RawData) {
				continue
			}

			if err := e.writeAtOffset(int(pos+ELF64_S_OFFSET), section.Offset); err != nil {
				continue
			}
			if err := e.writeAtOffset(int(pos+ELF64_S_SIZE), section.Size); err != nil {
				continue
			}
		} else {
			// Ensure we have enough data to write the offset and size
			if int(pos+ELF32_S_OFFSET+4) > len(e.RawData) || int(pos+ELF32_S_SIZE+4) > len(e.RawData) {
				continue
			}

			if err := e.writeAtOffset(int(pos+ELF32_S_OFFSET), uint32(section.Offset)); err != nil {
				continue
			}
			if err := e.writeAtOffset(int(pos+ELF32_S_SIZE), uint32(section.Size)); err != nil {
				continue
			}
		}
	}
	return nil
}

func (e *ELFFile) clearNameOffsetCache() {
	e.nameOffsets = nil
}

func (e *ELFFile) modifyHeaders(newSize uint64) error {
	if err := e.updateSectionHeaders(); err != nil {
		return err
	}
	for i := uint16(0); i < uint16(len(e.Segments)); i++ {
		if err := e.updateProgramHeader(i, newSize); err != nil {
			return err
		}
	}
	return nil
}
