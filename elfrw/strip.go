package elfrw

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
)

func (e *ELFFile) IsLittleEndian() bool {
	return e.RawData[5] == 1 // ELFDATA2LSB
}

func (e *ELFFile) GetEndian() binary.ByteOrder {
	if e.IsLittleEndian() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func (e *ELFFile) StripSections() error {
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
	return nil
}

func (e *ELFFile) StripDebugInfo() error {
	sectionCount := e.ELF.GetSectionCount()
	for i := uint16(0); i < sectionCount; i++ {
		name, err := e.ELF.GetSectionName(i)
		if err != nil {
			continue
		}

		if strings.HasPrefix(name, ".debug_") {
			header, err := e.ELF.GetSectionHeader(i)
			if err != nil {
				continue
			}
			if offset := header.GetFileOffset(); offset > 0 {
				err := e.ZeroFill(offset, int(header.GetSize()))
				if err != nil {
					return err
				}

				// Aggiorna anche la struttura Section
				for j := range e.Sections {
					if e.Sections[j].Index == i {
						e.Sections[j].Offset = 0
						e.Sections[j].Size = 0
						break
					}
				}
			}
		}
	}
	return nil
}

func (e *ELFFile) StripSymbols() error {
	symbolSections := []string{".symtab", ".dynsym"}
	for i, section := range e.Sections {
		for _, symSection := range symbolSections {
			if section.Name == symSection {
				// Azzera il contenuto della sezione
				if section.Offset > 0 && section.Size > 0 {
					err := e.ZeroFill(section.Offset, int(section.Size))
					if err != nil {
						return err
					}
				}

				// Aggiorna la struttura Section
				section.Offset = 0
				section.Size = 0
				e.Sections[i] = section
			}
		}
	}

	// Aggiorna i dati raw
	return e.UpdateSectionHeaders()
}

func (e *ELFFile) StripNonLoadable() error {
	for i, segment := range e.Segments {
		if !segment.Loadable {
			// Azzera il contenuto del segmento
			if segment.Offset > 0 && segment.Size > 0 {
				err := e.ZeroFill(segment.Offset, int(segment.Size))
				if err != nil {
					return err
				}
			}

			// Aggiorna la struttura Segment
			segment.Offset = 0
			segment.Size = 0
			e.Segments[i] = segment
		}
	}

	// Aggiorna i dati raw
	return e.UpdateProgramHeaders()
}

func (e *ELFFile) StripStrings() error {
	// Rimuove solo .strtab, evita di modificare .rodata
	stringSections := []string{".strtab"}
	for i, section := range e.Sections {
		for _, strSection := range stringSections {
			if section.Name == strSection {
				// Azzera il contenuto della sezione
				if section.Offset > 0 && section.Size > 0 {
					err := e.ZeroFill(section.Offset, int(section.Size))
					if err != nil {
						return err
					}
				}

				// Aggiorna la struttura Section
				section.Offset = 0
				section.Size = 0
				e.Sections[i] = section
			}
		}
	}

	// Aggiorna i dati raw
	return e.UpdateSectionHeaders()
}

// RandomizeSectionNames rinomina le sezioni in modo randomico
func (e *ELFFile) RandomizeSectionNames() error {
	// Trova l'indice della tabella delle stringhe delle sezioni
	// Questo valore è nell'header ELF a offset 62 (ELF64) o 50 (ELF32)
	var shStrNdxPos int
	if e.Is64Bit {
		shStrNdxPos = 62
	} else {
		shStrNdxPos = 50
	}

	endianness := e.GetEndian()
	var shstrtabIndex uint16

	if endianness == binary.LittleEndian {
		shstrtabIndex = binary.LittleEndian.Uint16(e.RawData[shStrNdxPos : shStrNdxPos+2])
	} else {
		shstrtabIndex = binary.BigEndian.Uint16(e.RawData[shStrNdxPos : shStrNdxPos+2])
	}

	// Ottieni il contenuto della tabella delle stringhe
	shstrtabContent, err := e.ELF.GetSectionContent(shstrtabIndex)
	if err != nil {
		return fmt.Errorf("impossibile leggere la tabella delle stringhe: %w", err)
	}

	// Ottieni l'header della tabella delle stringhe
	shstrtabHeader, err := e.ELF.GetSectionHeader(shstrtabIndex)
	if err != nil {
		return fmt.Errorf("impossibile leggere l'header della tabella delle stringhe: %w", err)
	}

	// Crea una nuova tabella delle stringhe
	newShstrtab := make([]byte, 0, len(shstrtabContent))
	newShstrtab = append(newShstrtab, 0) // Il primo byte deve essere 0

	// Mappa per tenere traccia dei nuovi offset dei nomi
	nameOffsets := make(map[string]uint32)

	// Genera nomi casuali per ogni sezione e aggiornali nella tabella
	for i := range e.Sections {
		if e.Sections[i].Name == "" {
			continue
		}

		// Genera un nome casuale (mantieni il punto iniziale per convenzione)
		randomName := fmt.Sprintf(".s%d", rand.Intn(10000))

		// Aggiungi il nome alla nuova tabella delle stringhe
		nameOffsets[e.Sections[i].Name] = uint32(len(newShstrtab))
		newShstrtab = append(newShstrtab, []byte(randomName)...)
		newShstrtab = append(newShstrtab, 0) // Terminatore null

		// Aggiorna il nome nella struttura Section
		e.Sections[i].Name = randomName
	}

	// Aggiorna la tabella delle stringhe nei dati raw
	shstrtabOffset := shstrtabHeader.GetFileOffset()
	copy(e.RawData[shstrtabOffset:shstrtabOffset+uint64(len(newShstrtab))], newShstrtab)

	// Se la nuova tabella è più piccola, riempi il resto con zeri
	if len(newShstrtab) < len(shstrtabContent) {
		for i := len(newShstrtab); i < len(shstrtabContent); i++ {
			e.RawData[shstrtabOffset+uint64(i)] = 0
		}
	}

	// Trova l'offset della tabella delle sezioni
	var shoffPos int
	if e.Is64Bit {
		shoffPos = 40
	} else {
		shoffPos = 32
	}

	var sectionHeaderOffset uint64
	if e.Is64Bit {
		if endianness == binary.LittleEndian {
			sectionHeaderOffset = binary.LittleEndian.Uint64(e.RawData[shoffPos : shoffPos+8])
		} else {
			sectionHeaderOffset = binary.BigEndian.Uint64(e.RawData[shoffPos : shoffPos+8])
		}
	} else {
		if endianness == binary.LittleEndian {
			sectionHeaderOffset = uint64(binary.LittleEndian.Uint32(e.RawData[shoffPos : shoffPos+4]))
		} else {
			sectionHeaderOffset = uint64(binary.BigEndian.Uint32(e.RawData[shoffPos : shoffPos+4]))
		}
	}

	// Calcola la dimensione dell'entry della tabella delle sezioni
	var shentsizePos int
	if e.Is64Bit {
		shentsizePos = 58
	} else {
		shentsizePos = 46
	}

	var sectionHeaderEntrySize uint16
	if endianness == binary.LittleEndian {
		sectionHeaderEntrySize = binary.LittleEndian.Uint16(e.RawData[shentsizePos : shentsizePos+2])
	} else {
		sectionHeaderEntrySize = binary.BigEndian.Uint16(e.RawData[shentsizePos : shentsizePos+2])
	}

	// Aggiorna gli offset dei nomi nella tabella delle sezioni
	for i := uint16(0); i < e.ELF.GetSectionCount(); i++ {
		oldName, err := e.ELF.GetSectionName(i)
		if err != nil {
			continue
		}

		// Calcola l'offset del campo name nell'header della sezione
		nameOffset := sectionHeaderOffset + uint64(i)*uint64(sectionHeaderEntrySize)

		// Il campo name è il primo campo nell'header della sezione
		if newOffset, ok := nameOffsets[oldName]; ok {
			// Aggiorna l'offset del nome nei dati raw
			err := WriteAtOffset(e.RawData, nameOffset, endianness, newOffset)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *ELFFile) ReadBytes(offset uint64, size int) ([]byte, error) {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return nil, fmt.Errorf("read beyond file limits: offset %d, size %d", offset, size)
	}
	result := make([]byte, size)
	copy(result, e.RawData[offset:offset+uint64(size)])
	return result, nil
}

func (e *ELFFile) ZeroFill(offset uint64, size int) error {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return fmt.Errorf("write beyond file limits: offset %d, size %d", offset, size)
	}
	for i := uint64(0); i < uint64(size); i++ {
		e.RawData[offset+i] = 0
	}
	return nil
}
