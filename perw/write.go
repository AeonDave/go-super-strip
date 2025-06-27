package perw

import (
	"encoding/binary"
	"fmt"
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
