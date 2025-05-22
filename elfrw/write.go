package elfrw

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func (e *ELFFile) ModifyHeaders(newSize uint64) error {
	endianness := e.GetEndian()
	var shoffPos, shNumPos, shStrNdxPos int

	if e.Is64Bit {
		shoffPos = 40
		shNumPos = 60
		shStrNdxPos = 62
	} else {
		shoffPos = 32
		shNumPos = 48
		shStrNdxPos = 50
	}

	var sectionHeaderOffset uint64
	if e.Is64Bit {
		sectionHeaderOffset = binary.BigEndian.Uint64(e.RawData[shoffPos : shoffPos+8])
		if e.RawData[5] == 1 { // ELFDATA2LSB
			sectionHeaderOffset = binary.LittleEndian.Uint64(e.RawData[shoffPos : shoffPos+8])
		}
	} else {
		sectionHeaderOffset = uint64(binary.BigEndian.Uint32(e.RawData[shoffPos : shoffPos+4]))
		if e.RawData[5] == 1 { // ELFDATA2LSB
			sectionHeaderOffset = uint64(binary.LittleEndian.Uint32(e.RawData[shoffPos : shoffPos+4]))
		}
	}

	if sectionHeaderOffset >= newSize {
		if e.Is64Bit {
			var zero uint64 = 0
			err := WriteAtOffset(e.RawData, uint64(shoffPos), endianness, zero)
			if err != nil {
				return err
			}
		} else {
			var zero uint32 = 0
			err := WriteAtOffset(e.RawData, uint64(shoffPos), endianness, zero)
			if err != nil {
				return err
			}
		}

		var zeroShort uint16 = 0
		err := WriteAtOffset(e.RawData, uint64(shNumPos), endianness, zeroShort)
		if err != nil {
			return err
		}
		err = WriteAtOffset(e.RawData, uint64(shStrNdxPos), endianness, zeroShort)
		if err != nil {
			return err
		}
	} else {
		err := e.UpdateSectionHeaders()
		if err != nil {
			return err
		}
	}
	segmentCount := e.ELF.GetSegmentCount()
	for i := uint16(0); i < segmentCount; i++ {
		phdr, err := e.ELF.GetProgramHeader(i)
		if err != nil {
			return fmt.Errorf("impossibile leggere l'intestazione di programma %d: %w", i, err)
		}
		phdrOffset := phdr.GetFileOffset()
		phdrFileSize := phdr.GetFileSize()
		var phdrTableOffset uint64
		if e.Is64Bit {
			phdrTableOffsetPos := 32
			phdrTableOffset = binary.BigEndian.Uint64(e.RawData[phdrTableOffsetPos : phdrTableOffsetPos+8])
			if e.RawData[5] == 1 { // ELFDATA2LSB
				phdrTableOffset = binary.LittleEndian.Uint64(e.RawData[phdrTableOffsetPos : phdrTableOffsetPos+8])
			}
		} else {
			phdrTableOffsetPos := 28
			phdrTableOffset = uint64(binary.BigEndian.Uint32(e.RawData[phdrTableOffsetPos : phdrTableOffsetPos+4]))
			if e.RawData[5] == 1 { // ELFDATA2LSB
				phdrTableOffset = uint64(binary.LittleEndian.Uint32(e.RawData[phdrTableOffsetPos : phdrTableOffsetPos+4]))
			}
		}

		var phdrEntrySize uint16
		if e.Is64Bit {
			phdrEntrySizePos := 54
			phdrEntrySize = binary.BigEndian.Uint16(e.RawData[phdrEntrySizePos : phdrEntrySizePos+2])
			if e.RawData[5] == 1 { // ELFDATA2LSB
				phdrEntrySize = binary.LittleEndian.Uint16(e.RawData[phdrEntrySizePos : phdrEntrySizePos+2])
			}
		} else {
			phdrEntrySizePos := 42
			phdrEntrySize = binary.BigEndian.Uint16(e.RawData[phdrEntrySizePos : phdrEntrySizePos+2])
			if e.RawData[5] == 1 { // ELFDATA2LSB
				phdrEntrySize = binary.LittleEndian.Uint16(e.RawData[phdrEntrySizePos : phdrEntrySizePos+2])
			}
		}
		phdrPos := phdrTableOffset + uint64(i)*uint64(phdrEntrySize)
		var offsetPos, fileSizePos uint64
		if e.Is64Bit {
			offsetPos = phdrPos + 8
			fileSizePos = phdrPos + 32
		} else {
			offsetPos = phdrPos + 4
			fileSizePos = phdrPos + 16
		}
		if phdrOffset >= newSize {
			if e.Is64Bit {
				err := WriteAtOffset(e.RawData, offsetPos, endianness, uint64(newSize))
				if err != nil {
					return err
				}
			} else {
				err := WriteAtOffset(e.RawData, offsetPos, endianness, uint32(newSize))
				if err != nil {
					return err
				}
			}
			if e.Is64Bit {
				err := WriteAtOffset(e.RawData, fileSizePos, endianness, uint64(0))
				if err != nil {
					return err
				}
			} else {
				err := WriteAtOffset(e.RawData, fileSizePos, endianness, uint32(0))
				if err != nil {
					return err
				}
			}
		} else if phdrOffset+phdrFileSize > newSize {
			newFileSize := newSize - phdrOffset
			if e.Is64Bit {
				err := WriteAtOffset(e.RawData, fileSizePos, endianness, uint64(newFileSize))
				if err != nil {
					return err
				}
			} else {
				err := WriteAtOffset(e.RawData, fileSizePos, endianness, uint32(newFileSize))
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (e *ELFFile) UpdateRawData() error {
	err := e.UpdateSectionHeaders()
	if err != nil {
		return err
	}
	err = e.UpdateProgramHeaders()
	if err != nil {
		return err
	}
	return nil
}

func (e *ELFFile) UpdateSectionHeaders() error {
	var sectionHeaderOffset uint64
	var shoffPos int
	if e.Is64Bit {
		shoffPos = 40
	} else {
		shoffPos = 32
	}
	endianness := e.GetEndian()
	if e.Is64Bit {
		sectionHeaderOffset = binary.BigEndian.Uint64(e.RawData[shoffPos : shoffPos+8])
		if e.RawData[5] == 1 { // ELFDATA2LSB
			sectionHeaderOffset = binary.LittleEndian.Uint64(e.RawData[shoffPos : shoffPos+8])
		}
	} else {
		sectionHeaderOffset = uint64(binary.BigEndian.Uint32(e.RawData[shoffPos : shoffPos+4]))
		if e.RawData[5] == 1 { // ELFDATA2LSB
			sectionHeaderOffset = uint64(binary.LittleEndian.Uint32(e.RawData[shoffPos : shoffPos+4]))
		}
	}
	if sectionHeaderOffset == 0 {
		return nil
	}
	var sectionHeaderEntrySize uint16
	var shentsizePos int
	if e.Is64Bit {
		shentsizePos = 58
	} else {
		shentsizePos = 46
	}
	sectionHeaderEntrySize = binary.BigEndian.Uint16(e.RawData[shentsizePos : shentsizePos+2])
	if e.RawData[5] == 1 { // ELFDATA2LSB
		sectionHeaderEntrySize = binary.LittleEndian.Uint16(e.RawData[shentsizePos : shentsizePos+2])
	}
	for i, section := range e.Sections {
		sectionHeaderPos := sectionHeaderOffset + uint64(i)*uint64(sectionHeaderEntrySize)

		// Aggiorna i campi dell'intestazione di sezione
		// Il campo name è il primo campo (offset 0)
		// Il campo type è il secondo campo (offset 4)
		// Il campo flags è il terzo campo (offset 8 per ELF32, offset 8 per ELF64)
		// Il campo addr è il quarto campo (offset 12 per ELF32, offset 16 per ELF64)
		// Il campo offset è il quinto campo (offset 16 per ELF32, offset 24 per ELF64)
		// Il campo size è il sesto campo (offset 20 per ELF32, offset 32 per ELF64)

		var offsetPos uint64
		if e.Is64Bit {
			offsetPos = sectionHeaderPos + 24
		} else {
			offsetPos = sectionHeaderPos + 16
		}

		if e.Is64Bit {
			err := WriteAtOffset(e.RawData, offsetPos, endianness, uint64(section.Offset))
			if err != nil {
				return err
			}
		} else {
			err := WriteAtOffset(e.RawData, offsetPos, endianness, uint32(section.Offset))
			if err != nil {
				return err
			}
		}

		var sizePos uint64
		if e.Is64Bit {
			sizePos = sectionHeaderPos + 32
		} else {
			sizePos = sectionHeaderPos + 20
		}

		if e.Is64Bit {
			err := WriteAtOffset(e.RawData, sizePos, endianness, uint64(section.Size))
			if err != nil {
				return err
			}
		} else {
			err := WriteAtOffset(e.RawData, sizePos, endianness, uint32(section.Size))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *ELFFile) UpdateProgramHeaders() error {
	var programHeaderOffset uint64
	var phoffPos int

	if e.Is64Bit {
		phoffPos = 32
	} else {
		phoffPos = 28
	}
	endianness := e.GetEndian()
	if e.Is64Bit {
		programHeaderOffset = binary.BigEndian.Uint64(e.RawData[phoffPos : phoffPos+8])
		if e.RawData[5] == 1 { // ELFDATA2LSB
			programHeaderOffset = binary.LittleEndian.Uint64(e.RawData[phoffPos : phoffPos+8])
		}
	} else {
		programHeaderOffset = uint64(binary.BigEndian.Uint32(e.RawData[phoffPos : phoffPos+4]))
		if e.RawData[5] == 1 { // ELFDATA2LSB
			programHeaderOffset = uint64(binary.LittleEndian.Uint32(e.RawData[phoffPos : phoffPos+4]))
		}
	}
	if programHeaderOffset == 0 {
		return nil
	}
	var programHeaderEntrySize uint16
	var phentsizePos int
	if e.Is64Bit {
		phentsizePos = 54
	} else {
		phentsizePos = 42
	}
	programHeaderEntrySize = binary.BigEndian.Uint16(e.RawData[phentsizePos : phentsizePos+2])
	if e.RawData[5] == 1 { // ELFDATA2LSB
		programHeaderEntrySize = binary.LittleEndian.Uint16(e.RawData[phentsizePos : phentsizePos+2])
	}
	for i, segment := range e.Segments {
		programHeaderPos := programHeaderOffset + uint64(i)*uint64(programHeaderEntrySize)

		// Aggiorna i campi dell'intestazione di programma
		// Il campo type è il primo campo (offset 0)
		// Il campo offset è il terzo campo (offset 4 per ELF32, offset 8 per ELF64)
		// Il campo vaddr è il quarto campo (offset 8 per ELF32, offset 16 per ELF64)
		// Il campo paddr è il quinto campo (offset 12 per ELF32, offset 24 per ELF64)
		// Il campo filesz è il sesto campo (offset 16 per ELF32, offset 32 per ELF64)
		// Il campo memsz è il settimo campo (offset 20 per ELF32, offset 40 per ELF64)
		// Il campo flags è il secondo campo per ELF64 (offset 4), l'ottavo campo per ELF32 (offset 24)

		var offsetPos uint64
		if e.Is64Bit {
			offsetPos = programHeaderPos + 8
		} else {
			offsetPos = programHeaderPos + 4
		}

		if e.Is64Bit {
			err := WriteAtOffset(e.RawData, offsetPos, endianness, uint64(segment.Offset))
			if err != nil {
				return err
			}
		} else {
			err := WriteAtOffset(e.RawData, offsetPos, endianness, uint32(segment.Offset))
			if err != nil {
				return err
			}
		}
		var fileSizePos uint64
		if e.Is64Bit {
			fileSizePos = programHeaderPos + 32
		} else {
			fileSizePos = programHeaderPos + 16
		}
		if e.Is64Bit {
			err := WriteAtOffset(e.RawData, fileSizePos, endianness, uint64(segment.Size))
			if err != nil {
				return err
			}
		} else {
			err := WriteAtOffset(e.RawData, fileSizePos, endianness, uint32(segment.Size))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *ELFFile) CommitChanges(newSize uint64) error {
	err := e.UpdateRawData()
	if err != nil {
		return fmt.Errorf("impossibile aggiornare i dati raw: %w", err)
	}
	_, err = e.File.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("impossibile riposizionare il file: %w", err)
	}
	_, err = e.File.Write(e.RawData[:newSize])
	if err != nil {
		return fmt.Errorf("impossibile scrivere nel file: %w", err)
	}
	err = e.File.Truncate(int64(newSize))
	if err != nil {
		return fmt.Errorf("impossibile ridimensionare il file: %w", err)
	}
	return nil
}

func WriteAtOffset(data []byte, offset uint64, endianness binary.ByteOrder, value interface{}) error {
	if offset >= uint64(len(data)) {
		return fmt.Errorf("offset fuori dai limiti: %d", offset)
	}
	var buf bytes.Buffer
	err := binary.Write(&buf, endianness, value)
	if err != nil {
		return fmt.Errorf("impossibile scrivere il valore: %w", err)
	}
	copy(data[offset:], buf.Bytes())
	return nil
}
