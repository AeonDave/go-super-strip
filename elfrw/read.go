package elfrw

import (
	"fmt"
	"os"

	"github.com/yalue/elf_reader"
)

type Section struct {
	Name   string
	Offset uint64
	Size   uint64
	Type   uint32
	Flags  uint64
	Index  uint16
}

type Segment struct {
	Offset   uint64
	Size     uint64
	Type     uint32
	Flags    uint32
	Loadable bool
	Index    uint16
}

type ELFFile struct {
	File     *os.File
	RawData  []byte
	ELF      elf_reader.ELFFile
	Is64Bit  bool
	FileName string
	Sections []Section
	Segments []Segment
}

func ReadELF(file *os.File) (*ELFFile, error) {
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("impossibile ottenere informazioni sul file: %w", err)
	}
	rawData := make([]byte, fileInfo.Size())
	_, err = file.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf("impossibile riposizionare il file: %w", err)
	}
	_, err = file.Read(rawData)
	if err != nil {
		return nil, fmt.Errorf("impossibile leggere il file: %w", err)
	}
	is64Bit := false
	if len(rawData) > 4 && rawData[4] == 2 { // ELFCLASS64
		is64Bit = true
	}
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

func (e *ELFFile) IsExecutableOrShared() bool {
	fileType := e.ELF.GetFileType()
	return fileType == elf_reader.ELFFileType(2) || fileType == elf_reader.ELFFileType(3)
}

func (e *ELFFile) CalculateMemorySize() (uint64, error) {
	var size uint64
	segmentCount := e.ELF.GetSegmentCount()
	var headerSize uint64
	if e.Is64Bit {
		headerSize = 64
	} else {
		headerSize = 52
	}
	size = headerSize
	for i := uint16(0); i < segmentCount; i++ {
		phdr, err := e.ELF.GetProgramHeader(i)
		if err != nil {
			return 0, fmt.Errorf("impossibile leggere l'intestazione di programma %d: %w", i, err)
		}
		if phdr.GetType() == elf_reader.ProgramHeaderType(0) {
			continue
		}
		segmentEnd := phdr.GetFileOffset() + phdr.GetFileSize()
		if segmentEnd > size {
			size = segmentEnd
		}
	}

	return size, nil
}

func (e *ELFFile) TruncateZeros(size uint64) (uint64, error) {
	if size > uint64(len(e.RawData)) {
		return size, fmt.Errorf("dimensione specificata maggiore della dimensione del file")
	}
	for size > 0 && e.RawData[size-1] == 0 {
		size--
	}
	return size, nil
}
