package elfrw

import (
	"fmt"
	"os"

	"github.com/yalue/elf_reader"
)

// Section rappresenta una sezione ELF
type Section struct {
	Name   string
	Offset uint64
	Size   uint64
	Type   uint32
	Flags  uint64
	Index  uint16
}

// Segment rappresenta un segmento ELF
type Segment struct {
	Offset   uint64
	Size     uint64
	Type     uint32
	Flags    uint32
	Loadable bool
	Index    uint16
}

// ELFFile rappresenta un file ELF con le sue strutture principali
type ELFFile struct {
	File     *os.File
	RawData  []byte
	ELF      elf_reader.ELFFile
	Is64Bit  bool
	FileName string
	Sections []Section
	Segments []Segment
}

// ReadELF legge un file ELF e restituisce una struttura ELFFile
func ReadELF(file *os.File) (*ELFFile, error) {
	// Ottiene le informazioni sul file
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("impossibile ottenere informazioni sul file: %w", err)
	}

	// Legge l'intero file in memoria
	rawData := make([]byte, fileInfo.Size())
	_, err = file.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf("impossibile riposizionare il file: %w", err)
	}

	_, err = file.Read(rawData)
	if err != nil {
		return nil, fmt.Errorf("impossibile leggere il file: %w", err)
	}

	// Determina se il file è ELF a 32 o 64 bit
	is64Bit := false
	if len(rawData) > 4 && rawData[4] == 2 { // ELFCLASS64
		is64Bit = true
	}

	// Analizza il file ELF
	elfFile, parseErr := elf_reader.ParseELFFile(rawData)
	if parseErr != nil {
		return nil, fmt.Errorf("impossibile analizzare il file ELF: %w", parseErr)
	}

	ef := &ELFFile{
		File:     file,
		RawData:  rawData,
		ELF:      elfFile,
		Is64Bit:  is64Bit,
		FileName: fileInfo.Name(),
		Sections: []Section{},
		Segments: []Segment{},
	}

	// Popola le sezioni
	sectionCount := ef.ELF.GetSectionCount()
	for i := uint16(0); i < sectionCount; i++ {
		header, err := ef.ELF.GetSectionHeader(i)
		if err != nil {
			continue
		}

		name, _ := ef.ELF.GetSectionName(i)

		section := Section{
			Name:   name,
			Offset: header.GetFileOffset(),
			Size:   header.GetSize(),
			Type:   uint32(header.GetType()),
			Flags:  0, // Converti le flags in base al tipo
			Index:  i,
		}

		ef.Sections = append(ef.Sections, section)
	}

	// Popola i segmenti
	segmentCount := ef.ELF.GetSegmentCount()
	for i := uint16(0); i < segmentCount; i++ {
		phdr, err := ef.ELF.GetProgramHeader(i)
		if err != nil {
			continue
		}

		segment := Segment{
			Offset:   phdr.GetFileOffset(),
			Size:     phdr.GetFileSize(),
			Type:     uint32(phdr.GetType()),
			Flags:    uint32(phdr.GetFlags()),
			Loadable: phdr.GetType() == elf_reader.ProgramHeaderType(1), // PT_LOAD = 1
			Index:    i,
		}

		ef.Segments = append(ef.Segments, segment)
	}

	return ef, nil
}

// IsExecutableOrShared verifica se il file è un eseguibile o una libreria condivisa
func (e *ELFFile) IsExecutableOrShared() bool {
	fileType := e.ELF.GetFileType()
	// Confronta con le costanti ELFTypeExecutable (2) e ELFTypeSharedObject (3)
	return fileType == elf_reader.ELFFileType(2) || fileType == elf_reader.ELFFileType(3)
}

// CalculateMemorySize determina l'offset dell'ultimo byte del file
// che è referenziato da una voce nella tabella delle intestazioni di programma
func (e *ELFFile) CalculateMemorySize() (uint64, error) {
	// Inizia impostando la dimensione per includere l'header ELF e
	// la tabella completa delle intestazioni di programma
	var size uint64

	// Ottiene il numero di segmenti (program headers)
	segmentCount := e.ELF.GetSegmentCount()

	// Calcola la dimensione iniziale includendo l'header ELF e la tabella dei program header
	// Poiché GetHeaderSize non esiste, usiamo valori standard: 52 per ELF32, 64 per ELF64
	var headerSize uint64
	if e.Is64Bit {
		headerSize = 64
	} else {
		headerSize = 52
	}
	size = headerSize

	// Estende la dimensione per includere qualsiasi dato a cui fa riferimento
	// la tabella delle intestazioni di programma
	for i := uint16(0); i < segmentCount; i++ {
		phdr, err := e.ELF.GetProgramHeader(i)
		if err != nil {
			return 0, fmt.Errorf("impossibile leggere l'intestazione di programma %d: %w", i, err)
		}

		// Salta i segmenti di tipo NULL (0)
		if phdr.GetType() == elf_reader.ProgramHeaderType(0) {
			continue
		}

		// Calcola la fine del segmento nel file
		segmentEnd := phdr.GetFileOffset() + phdr.GetFileSize()
		if segmentEnd > size {
			size = segmentEnd
		}
	}

	return size, nil
}

// TruncateZeros esamina i byte alla fine della dimensione del file
// e riduce la dimensione per escludere eventuali byte zero finali
func (e *ELFFile) TruncateZeros(size uint64) (uint64, error) {
	// Verifica che la dimensione non superi la dimensione del file
	if size > uint64(len(e.RawData)) {
		return size, fmt.Errorf("dimensione specificata maggiore della dimensione del file")
	}

	// Esamina i byte dalla fine della dimensione specificata
	// e riduce la dimensione per escludere eventuali byte zero finali
	for size > 0 && e.RawData[size-1] == 0 {
		size--
	}

	return size, nil
}
