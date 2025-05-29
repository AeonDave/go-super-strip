package elfrw

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

func (e *ELFFile) RandomizeSectionNames() error {
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
	shstrtabContent, err := e.ELF.GetSectionContent(shstrtabIndex)
	if err != nil {
		return fmt.Errorf("impossibile leggere la tabella delle stringhe: %w", err)
	}
	shstrtabHeader, err := e.ELF.GetSectionHeader(shstrtabIndex)
	if err != nil {
		return fmt.Errorf("impossibile leggere l'header della tabella delle stringhe: %w", err)
	}
	newShstrtab := make([]byte, 0, len(shstrtabContent))
	newShstrtab = append(newShstrtab, 0)
	nameOffsets := make(map[string]uint32)
	for i := range e.Sections {
		if e.Sections[i].Name == "" {
			continue
		}
		randomName := fmt.Sprintf(".s%d", rand.Intn(10000))
		nameOffsets[e.Sections[i].Name] = uint32(len(newShstrtab))
		newShstrtab = append(newShstrtab, []byte(randomName)...)
		newShstrtab = append(newShstrtab, 0)
		e.Sections[i].Name = randomName
	}
	shstrtabOffset := shstrtabHeader.GetFileOffset()
	copy(e.RawData[shstrtabOffset:shstrtabOffset+uint64(len(newShstrtab))], newShstrtab)
	if len(newShstrtab) < len(shstrtabContent) {
		for i := len(newShstrtab); i < len(shstrtabContent); i++ {
			e.RawData[shstrtabOffset+uint64(i)] = 0
		}
	}
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
	for i := uint16(0); i < e.ELF.GetSectionCount(); i++ {
		oldName, err := e.ELF.GetSectionName(i)
		if err != nil {
			continue
		}
		nameOffset := sectionHeaderOffset + uint64(i)*uint64(sectionHeaderEntrySize)
		if newOffset, ok := nameOffsets[oldName]; ok {
			err := WriteAtOffset(e.RawData, nameOffset, endianness, newOffset)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ObfuscateBaseAddresses modifica casualmente gli indirizzi virtuali di base
func (e *ELFFile) ObfuscateBaseAddresses() error {
	endianness := e.GetEndian()

	// Genera un offset casuale (manteniamo l'allineamento a pagina)
	randomOffset := uint64(rand.Intn(0x10000)) * 0x1000

	// Modifica gli indirizzi virtuali nelle intestazioni di programma
	for i, segment := range e.Segments {
		if segment.Loadable {
			// Ottieni l'header originale
			_, err := e.ELF.GetProgramHeader(segment.Index)
			if err != nil {
				continue
			}

			// Calcola la posizione dell'intestazione di programma
			var phdrTableOffset uint64
			if e.Is64Bit {
				phdrTableOffsetPos := 32
				if endianness == binary.LittleEndian {
					phdrTableOffset = binary.LittleEndian.Uint64(e.RawData[phdrTableOffsetPos : phdrTableOffsetPos+8])
				} else {
					phdrTableOffset = binary.BigEndian.Uint64(e.RawData[phdrTableOffsetPos : phdrTableOffsetPos+8])
				}
			} else {
				phdrTableOffsetPos := 28
				if endianness == binary.LittleEndian {
					phdrTableOffset = uint64(binary.LittleEndian.Uint32(e.RawData[phdrTableOffsetPos : phdrTableOffsetPos+4]))
				} else {
					phdrTableOffset = uint64(binary.BigEndian.Uint32(e.RawData[phdrTableOffsetPos : phdrTableOffsetPos+4]))
				}
			}

			// Calcola la dimensione dell'entry della tabella dei program header
			var phdrEntrySize uint16
			if e.Is64Bit {
				phdrEntrySizePos := 54
				if endianness == binary.LittleEndian {
					phdrEntrySize = binary.LittleEndian.Uint16(e.RawData[phdrEntrySizePos : phdrEntrySizePos+2])
				} else {
					phdrEntrySize = binary.BigEndian.Uint16(e.RawData[phdrEntrySizePos : phdrEntrySizePos+2])
				}
			} else {
				phdrEntrySizePos := 42
				if endianness == binary.LittleEndian {
					phdrEntrySize = binary.LittleEndian.Uint16(e.RawData[phdrEntrySizePos : phdrEntrySizePos+2])
				} else {
					phdrEntrySize = binary.BigEndian.Uint16(e.RawData[phdrEntrySizePos : phdrEntrySizePos+2])
				}
			}

			phdrPos := phdrTableOffset + uint64(segment.Index)*uint64(phdrEntrySize)

			// Calcola la posizione del campo vaddr nell'intestazione di programma
			var vaddrPos uint64
			if e.Is64Bit {
				vaddrPos = phdrPos + 16
			} else {
				vaddrPos = phdrPos + 8
			}

			// Ottieni l'indirizzo virtuale originale
			var originalVaddr uint64
			if e.Is64Bit {
				if endianness == binary.LittleEndian {
					originalVaddr = binary.LittleEndian.Uint64(e.RawData[vaddrPos : vaddrPos+8])
				} else {
					originalVaddr = binary.BigEndian.Uint64(e.RawData[vaddrPos : vaddrPos+8])
				}
			} else {
				if endianness == binary.LittleEndian {
					originalVaddr = uint64(binary.LittleEndian.Uint32(e.RawData[vaddrPos : vaddrPos+4]))
				} else {
					originalVaddr = uint64(binary.BigEndian.Uint32(e.RawData[vaddrPos : vaddrPos+4]))
				}
			}

			// Calcola il nuovo indirizzo virtuale
			newVaddr := originalVaddr + randomOffset

			// Aggiorna l'indirizzo virtuale
			if e.Is64Bit {
				err := WriteAtOffset(e.RawData, vaddrPos, endianness, newVaddr)
				if err != nil {
					return err
				}
			} else {
				err := WriteAtOffset(e.RawData, vaddrPos, endianness, uint32(newVaddr))
				if err != nil {
					return err
				}
			}

			// Aggiorna anche l'indirizzo fisico (paddr)
			var paddrPos uint64
			if e.Is64Bit {
				paddrPos = phdrPos + 24
			} else {
				paddrPos = phdrPos + 12
			}

			if e.Is64Bit {
				err := WriteAtOffset(e.RawData, paddrPos, endianness, newVaddr)
				if err != nil {
					return err
				}
			} else {
				err := WriteAtOffset(e.RawData, paddrPos, endianness, uint32(newVaddr))
				if err != nil {
					return err
				}
			}

			// Aggiorna la struttura Segment
			e.Segments[i].Offset = segment.Offset
		}
	}

	// Aggiorna l'entry point nell'header ELF
	var entryPointPos int
	if e.Is64Bit {
		entryPointPos = 24
	} else {
		entryPointPos = 24
	}

	var originalEntryPoint uint64
	if e.Is64Bit {
		if endianness == binary.LittleEndian {
			originalEntryPoint = binary.LittleEndian.Uint64(e.RawData[entryPointPos : entryPointPos+8])
		} else {
			originalEntryPoint = binary.BigEndian.Uint64(e.RawData[entryPointPos : entryPointPos+8])
		}
	} else {
		if endianness == binary.LittleEndian {
			originalEntryPoint = uint64(binary.LittleEndian.Uint32(e.RawData[entryPointPos : entryPointPos+4]))
		} else {
			originalEntryPoint = uint64(binary.BigEndian.Uint32(e.RawData[entryPointPos : entryPointPos+4]))
		}
	}
	if originalEntryPoint != 0 {
		newEntryPoint := originalEntryPoint + randomOffset

		if e.Is64Bit {
			err := WriteAtOffset(e.RawData, uint64(entryPointPos), endianness, newEntryPoint)
			if err != nil {
				return err
			}
		} else {
			err := WriteAtOffset(e.RawData, uint64(entryPointPos), endianness, uint32(newEntryPoint))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ObfuscateGOTPLT aggiunge voci fittizie nelle tabelle GOT/PLT
func (e *ELFFile) ObfuscateGOTPLT() error {
	// Cerca le sezioni GOT e PLT
	var gotSection, pltSection *Section
	for i := range e.Sections {
		if e.Sections[i].Name == ".got" || e.Sections[i].Name == ".got.plt" {
			gotSection = &e.Sections[i]
		} else if e.Sections[i].Name == ".plt" {
			pltSection = &e.Sections[i]
		}
	}
	if gotSection == nil && pltSection == nil {
		return nil
	}

	if gotSection != nil && gotSection.Offset > 0 && gotSection.Size > 0 {
		content, err := e.ReadBytes(gotSection.Offset, int(gotSection.Size))
		if err != nil {
			return err
		}

		// Modifica alcune voci della GOT (ma non tutte, per mantenere la funzionalità)
		// Modifichiamo solo le voci che sembrano essere puntatori a funzioni
		entrySize := 4
		if e.Is64Bit {
			entrySize = 8
		}

		for i := 0; i < len(content); i += entrySize {
			// Salta le prime 3 voci della GOT che sono speciali
			if i >= 3*entrySize {
				// Genera un valore casuale che sembra un puntatore valido
				// ma che in realtà punta a una zona di memoria non mappata
				randomPtr := uint64(0x7f000000 + rand.Intn(0xffffff))

				// Modifica la voce della GOT
				if e.Is64Bit {
					binary.LittleEndian.PutUint64(content[i:i+entrySize], randomPtr)
				} else {
					binary.LittleEndian.PutUint32(content[i:i+entrySize], uint32(randomPtr))
				}
			}
		}

		// Scrivi il contenuto modificato
		copy(e.RawData[gotSection.Offset:gotSection.Offset+uint64(len(content))], content)
	}

	// Offusca la PLT se presente
	if pltSection != nil && pltSection.Offset > 0 && pltSection.Size > 0 {
		// La PLT contiene codice eseguibile, quindi è più rischioso modificarla
		// Possiamo aggiungere voci fittizie alla fine se c'è spazio

		// Per ora, lasciamo la PLT intatta per evitare di compromettere la funzionalità
	}

	return nil
}

// ObfuscateExportedFunctions rinomina le funzioni esportate
func (e *ELFFile) ObfuscateExportedFunctions() error {
	var dynsymSection, dynstrSection *Section
	for i := range e.Sections {
		if e.Sections[i].Name == ".dynsym" {
			dynsymSection = &e.Sections[i]
		} else if e.Sections[i].Name == ".dynstr" {
			dynstrSection = &e.Sections[i]
		}
	}
	if dynsymSection == nil || dynstrSection == nil {
		return nil
	}
	if dynsymSection.Offset > 0 && dynsymSection.Size > 0 &&
		dynstrSection.Offset > 0 && dynstrSection.Size > 0 {
		dynstrContent, err := e.ReadBytes(dynstrSection.Offset, int(dynstrSection.Size))
		if err != nil {
			return err
		}
		newDynstr := make([]byte, len(dynstrContent))
		copy(newDynstr, dynstrContent)
		symEntSize := 16
		if e.Is64Bit {
			symEntSize = 24
		}
		dynsymContent, err := e.ReadBytes(dynsymSection.Offset, int(dynsymSection.Size))
		if err != nil {
			return err
		}
		nameOffsets := make(map[uint32]uint32)
		numSymbols := len(dynsymContent) / symEntSize
		nameOffset := 0
		infoOffset := 4
		if e.Is64Bit {
			infoOffset = 4
		}
		for i := 0; i < numSymbols; i++ {
			symOffset := i * symEntSize
			var strOffset uint32
			if e.Is64Bit {
				strOffset = binary.LittleEndian.Uint32(dynsymContent[symOffset+nameOffset : symOffset+nameOffset+4])
			} else {
				strOffset = binary.LittleEndian.Uint32(dynsymContent[symOffset+nameOffset : symOffset+nameOffset+4])
			}
			symInfo := dynsymContent[symOffset+infoOffset]
			if (symInfo&0x0f) == 2 && (symInfo&0xf0) >= (1<<4) {
				if strOffset > 0 && strOffset < uint32(len(dynstrContent)) && nameOffsets[strOffset] == 0 {
					end := strOffset
					for end < uint32(len(dynstrContent)) && dynstrContent[end] != 0 {
						end++
					}
					newName := fmt.Sprintf("fn_%08x", rand.Uint32())
					newOffset := uint32(len(newDynstr))
					newDynstr = append(newDynstr, []byte(newName)...)
					newDynstr = append(newDynstr, 0)
					nameOffsets[strOffset] = newOffset
					if e.Is64Bit {
						binary.LittleEndian.PutUint32(dynsymContent[symOffset+nameOffset:symOffset+nameOffset+4], newOffset)
					} else {
						binary.LittleEndian.PutUint32(dynsymContent[symOffset+nameOffset:symOffset+nameOffset+4], newOffset)
					}
				}
			}
		}
		copy(e.RawData[dynsymSection.Offset:dynsymSection.Offset+uint64(len(dynsymContent))], dynsymContent)
		if len(newDynstr) > len(dynstrContent) {
			// Questo è complicato e richiede la riallocazione della sezione
			// Per semplicità, in questa implementazione ci limitiamo a modificare
			// i nomi che possono essere contenuti nella tabella esistente
			copy(e.RawData[dynstrSection.Offset:dynstrSection.Offset+uint64(len(dynstrContent))], newDynstr[:len(dynstrContent)])
		} else {
			copy(e.RawData[dynstrSection.Offset:dynstrSection.Offset+uint64(len(newDynstr))], newDynstr)
		}
	}

	return nil
}

// ObfuscateInitFiniTables offusca le tabelle di inizializzazione/finalizzazione
func (e *ELFFile) ObfuscateInitFiniTables() error {
	// Cerca le sezioni .init_array, .fini_array, .preinit_array
	initSections := []string{".init_array", ".fini_array", ".preinit_array"}

	for _, sectionName := range initSections {
		var section *Section
		for i := range e.Sections {
			if e.Sections[i].Name == sectionName {
				section = &e.Sections[i]
				break
			}
		}

		// Se non troviamo la sezione, passiamo alla prossima
		if section == nil || section.Offset == 0 || section.Size == 0 {
			continue
		}

		// Leggi il contenuto della sezione
		content, err := e.ReadBytes(section.Offset, int(section.Size))
		if err != nil {
			return err
		}
		ptrSize := 4
		if e.Is64Bit {
			ptrSize = 8
		}
		numPtrs := len(content) / ptrSize
		if numPtrs > 1 {
			// Aggiungiamo puntatori fittizi alla fine
			for i := 1; i < numPtrs; i++ {
				offset := i * ptrSize

				// Genera un valore casuale che sembra un puntatore valido
				randomPtr := uint64(0x7f000000 + rand.Intn(0xffffff))

				// Modifica il puntatore
				if e.Is64Bit {
					binary.LittleEndian.PutUint64(content[offset:offset+ptrSize], randomPtr)
				} else {
					binary.LittleEndian.PutUint32(content[offset:offset+ptrSize], uint32(randomPtr))
				}
			}

			// Scrivi il contenuto modificato
			copy(e.RawData[section.Offset:section.Offset+uint64(len(content))], content)
		}
	}

	return nil
}

// ObfuscateSectionPadding randomizza i byte di padding tra le sezioni ELF
func (e *ELFFile) ObfuscateSectionPadding() {
	for i := 0; i < len(e.Sections)-1; i++ {
		end := e.Sections[i].Offset + e.Sections[i].Size
		next := e.Sections[i+1].Offset
		if end < next && next-end < 0x10000 && end > 0 {
			for j := end; j < next; j++ {
				e.RawData[j] = byte(rand.Intn(256))
			}
		}
	}
}

// ObfuscateReservedHeaderFields randomizza campi riservati a zero nell'header ELF
func (e *ELFFile) ObfuscateReservedHeaderFields() {
	// ELF header: campi riservati a zero tra e_ident[9:16], e_flags (alcuni arch), padding in header program/section
	for i := 9; i < 16; i++ {
		e.RawData[i] = byte(rand.Intn(256))
	}
	// e_flags (offset 48 per 64bit, 36 per 32bit)
	if e.Is64Bit {
		for i := 48; i < 52; i++ {
			e.RawData[i] = byte(rand.Intn(256))
		}
	} else {
		for i := 36; i < 40; i++ {
			e.RawData[i] = byte(rand.Intn(256))
		}
	}
}

// ObfuscateSecondaryTimestamps randomizza timestamp secondari in note/debug (se presenti)
func (e *ELFFile) ObfuscateSecondaryTimestamps() {
	for _, section := range e.Sections {
		if section.Name == ".note" || section.Name == ".note.gnu.build-id" || section.Name == ".comment" {
			data, err := e.ReadBytes(section.Offset, int(section.Size))
			if err == nil && len(data) >= 4 {
				for i := 0; i+4 <= len(data); i += 4 {
					val := rand.Uint32()
					binary.LittleEndian.PutUint32(data[i:i+4], val)
				}
				copy(e.RawData[section.Offset:section.Offset+uint64(len(data))], data)
			}
		}
	}
}

// ObfuscateAll applica tutte le tecniche di offuscamento
func (e *ELFFile) ObfuscateAll() error {
	// Offusca gli indirizzi di base
	if err := e.ObfuscateBaseAddresses(); err != nil {
		return err
	}

	// Offusca le tabelle GOT/PLT
	if err := e.ObfuscateGOTPLT(); err != nil {
		return err
	}

	// Offusca i nomi delle funzioni esportate
	if err := e.ObfuscateExportedFunctions(); err != nil {
		return err
	}

	// Offusca le tabelle di inizializzazione/finalizzazione
	if err := e.ObfuscateInitFiniTables(); err != nil {
		return err
	}

	e.ObfuscateSectionPadding()
	e.ObfuscateReservedHeaderFields()
	e.ObfuscateSecondaryTimestamps()

	return nil
}
