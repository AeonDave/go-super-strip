package perw

import (
	"encoding/binary"
	"fmt"
	"io"
)

func WriteAtOffset(rawData []byte, offset int64, value interface{}) error {
	switch v := value.(type) {
	case uint32:
		if int(offset)+4 > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		binary.LittleEndian.PutUint32(rawData[int(offset):int(offset)+4], v)
	case uint64:
		if int(offset)+8 > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		binary.LittleEndian.PutUint64(rawData[int(offset):int(offset)+8], v)
	case uint16:
		if int(offset)+2 > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		binary.LittleEndian.PutUint16(rawData[int(offset):int(offset)+2], v)
	case uint8:
		if int(offset) >= len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		rawData[int(offset)] = v
	case []byte:
		if int(offset)+len(v) > len(rawData) {
			return fmt.Errorf("offset out of range: %d", offset)
		}
		copy(rawData[int(offset):int(offset)+len(v)], v)
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}
	return nil
}

func (p *PEFile) Save(updateHeaders bool, newSize int64) error {
	if p.File == nil {
		return fmt.Errorf("invalid file reference")
	}

	if newSize > 0 && int64(len(p.RawData)) > newSize {
		p.RawData = p.RawData[:newSize]
	}

	if updateHeaders && p.updateHeadersAtomic() != nil {
		return fmt.Errorf("failed to update headers")
	}

	if err := p.writeRawData(); err != nil {
		return err
	}
	return p.truncateFile()
}

func (p *PEFile) updateHeadersAtomic() error {
	if err := p.UpdateCOFFHeader(); err != nil {
		return fmt.Errorf("failed to update COFF header: %w", err)
	}
	return nil
}
func (p *PEFile) writeRawData() error {
	if _, err := p.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("repositioning file failed: %w", err)
	}
	if _, err := p.File.Write(p.RawData); err != nil {
		return fmt.Errorf("writing to disk failed: %w", err)
	}
	return nil
}

func (p *PEFile) truncateFile() error {
	if err := p.File.Truncate(int64(len(p.RawData))); err != nil {
		return fmt.Errorf("failed to resize file: %w", err)
	}
	return nil
}

func (p *PEFile) saveWithAppendOnly() error {
	currentInfo, err := p.File.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	originalSize := currentInfo.Size()
	if int64(len(p.RawData)) <= originalSize {
		return nil
	}

	newData := p.RawData[originalSize:]
	if _, err := p.File.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("failed to seek to end of file: %w", err)
	}

	if _, err := p.File.Write(newData); err != nil {
		return fmt.Errorf("failed to append new data: %w", err)
	}

	return nil
}

func (p *PEFile) UpdateCOFFHeader() error {
	if len(p.RawData) < PE_DOS_HEADER_SIZE {
		return fmt.Errorf("file too small for PE structure")
	}

	coffHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[PE_ELFANEW_OFFSET:PE_ELFANEW_OFFSET+4])) + PE_SIGNATURE_SIZE
	return WriteAtOffset(p.RawData, coffHeaderOffset+PE_SECTIONS_OFFSET, uint16(len(p.Sections)))
}
