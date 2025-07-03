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

func (e *ELFFile) writeAtOffset(pos int, value interface{}) error {
	return WriteAtOffset(e.RawData, int64(pos), value, e.GetEndian())
}

func (e *ELFFile) Save(updateHeaders bool, newSize int64) error {
	if e.File == nil {
		return fmt.Errorf("invalid file reference")
	}
	if newSize > 0 && int64(len(e.RawData)) > newSize {
		e.RawData = e.RawData[:newSize]
	}
	if updateHeaders {
		if err := e.ModifyHeaders(uint64(len(e.RawData))); err != nil {
			return err
		}
	}
	if err := e.writeRawData(); err != nil {
		return err
	}
	if err := e.truncateFile(); err != nil {
		return err
	}
	if err := e.File.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}
	return nil
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
	pos := e.getProgramHeaderPosition(index)

	if headerOffset >= newSize {
		return e.writeProgramHeaderOffsets(pos, newSize, 0)
	} else if headerOffset+headerSize > newSize {
		newFileSize := newSize - headerOffset
		return e.writeProgramHeaderOffsets(pos, headerOffset, newFileSize)
	}
	return nil
}

func (e *ELFFile) getProgramHeaderPosition(index uint16) uint64 {
	if e.Is64Bit {
		phOffset := e.readUint64(elf64E_phoff_offset)
		entrySize := uint64(e.readUint16(elf64E_phentsize_offset))
		return phOffset + uint64(index)*entrySize
	}
	offset := uint64(e.readUint32(elf32E_phoff_offset))
	entrySize := uint64(e.readUint16(elf32E_phentsize_offset))
	return offset + uint64(index)*entrySize
}

func (e *ELFFile) writeProgramHeaderOffsets(pos, offset, size uint64) error {
	if e.Is64Bit {
		if err := e.writeAtOffset(int(pos+elf64P_offset), offset); err != nil {
			return err
		}
		return e.writeAtOffset(int(pos+elf64P_filesz), size)
	}
	// 32-bit
	if err := e.writeAtOffset(int(pos+elf32P_offset), uint32(offset)); err != nil {
		return err
	}
	return e.writeAtOffset(int(pos+elf32P_filesz), uint32(size))
}

func (e *ELFFile) UpdateSectionHeaders() error {
	shoffPos, _, _ := e.getHeaderPositions()
	sectionHeaderOffset := e.getSectionHeaderOffset(shoffPos)
	if sectionHeaderOffset == 0 {
		return nil
	}

	var entrySize uint64
	if e.Is64Bit {
		entrySize = uint64(e.readUint16(elf64E_shentsize_offset))
	} else {
		entrySize = uint64(e.readUint16(elf32E_shentsize_offset))
	}

	for i, section := range e.Sections {
		pos := sectionHeaderOffset + uint64(i)*entrySize
		if e.Is64Bit {
			if err := e.writeAtOffset(int(pos+elf64S_offset), section.Offset); err != nil {
				return err
			}
			if err := e.writeAtOffset(int(pos+elf64S_size), section.Size); err != nil {
				return err
			}
		} else {
			if err := e.writeAtOffset(int(pos+elf32S_offset), uint32(section.Offset)); err != nil {
				return err
			}
			if err := e.writeAtOffset(int(pos+elf32S_size), uint32(section.Size)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *ELFFile) clearNameOffsetCache() {
	e.nameOffsets = nil
}

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
	for i := uint16(0); i < uint16(len(e.Segments)); i++ {
		if err := e.updateProgramHeader(i, newSize); err != nil {
			return err
		}
	}
	return nil
}
