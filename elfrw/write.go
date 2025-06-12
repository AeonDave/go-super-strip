package elfrw

import (
	"encoding/binary"
	"fmt"
	"io"
)

func (e *ELFFile) ModifyHeaders(newSize uint64) error {
	shoffPos, shNumPos, shStrNdxPos := e.getHeaderPositions()
	sectionHeaderOffset := e.getSectionHeaderOffset(shoffPos)

	if sectionHeaderOffset >= newSize {
		if err := e.clearSectionHeaders(shoffPos, shNumPos, shStrNdxPos); err != nil {
			return err
		}
	} else if err := e.UpdateSectionHeaders(); err != nil {
		return err
	}

	for i := uint16(0); i < e.ELF.GetSegmentCount(); i++ {
		if err := e.updateProgramHeader(i, newSize); err != nil {
			return err
		}
	}
	return nil
}

func (e *ELFFile) UpdateRawData() error {
	if err := e.UpdateSectionHeaders(); err != nil {
		return err
	}
	return e.UpdateProgramHeaders()
}

func (e *ELFFile) CommitChanges(newSize uint64) error {
	if err := e.ModifyHeaders(newSize); err != nil {
		return fmt.Errorf("failed to modify headers: %w", err)
	}
	if _, err := e.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to reposition file: %w", err)
	}
	if _, err := e.File.Write(e.RawData[:newSize]); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	if err := e.File.Truncate(int64(newSize)); err != nil {
		return fmt.Errorf("failed to resize file: %w", err)
	}
	return nil
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
			if err := e.writeAtOffset(int(pos+32), segment.Size); err != nil {
				return err
			}
		} else {
			if err := e.writeAtOffset(int(pos+4), uint32(segment.Offset)); err != nil {
				return err
			}
			if err := e.writeAtOffset(int(pos+16), uint32(segment.Size)); err != nil {
				return err
			}
		}
	}
	return nil
}

// WriteAtOffset writes a value to RawData at a specific offset with the given endianness.
func WriteAtOffset(rawData []byte, offset uint64, endian binary.ByteOrder, value interface{}) error {
	var size int
	switch value.(type) {
	case uint16:
		size = 2
	case uint32:
		size = 4
	case uint64:
		size = 8
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}

	// Check for integer overflow in the offset calculation
	if offset > uint64(len(rawData)) {
		return fmt.Errorf("offset too large: %d (file size: %d)", offset, len(rawData))
	}

	// Check if we have enough space to write
	if int(offset)+size > len(rawData) {
		return fmt.Errorf("write would exceed buffer limits: offset %d + size %d > length %d",
			offset, size, len(rawData))
	}

	buf := make([]byte, size)
	switch v := value.(type) {
	case uint16:
		endian.PutUint16(buf, v)
	case uint32:
		endian.PutUint32(buf, v)
	case uint64:
		endian.PutUint64(buf, v)
	}
	copy(rawData[offset:offset+uint64(size)], buf)
	return nil
}
