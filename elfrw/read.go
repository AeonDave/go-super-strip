package elfrw

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"unsafe"
)

var (
	ErrInvalidELF      = errors.New("invalid ELF file")
	ErrUnsupportedType = errors.New("unsupported ELF type")
	ErrReadError       = errors.New("failed to read ELF data")
)

const (
	elf32HeaderSize = 52
	elf64HeaderSize = 64
	elfIdentSize    = 16
)

// ReadEhdr legge l'header ELF con strategia di fallback ottimizzata
func ReadEhdr(elfFile *elf.File) (*Ehdr, error) {
	if elfFile == nil {
		return nil, ErrInvalidELF
	}

	// Tentativo di lettura diretta tramite reflection (più completo)
	if ehdr, err := readEhdrDirect(elfFile); err == nil {
		return ehdr, nil
	}

	// Fallback sicuro usando solo API pubbliche
	return readEhdrSafe(elfFile)
}

// readEhdrDirect usa reflection per accedere al ReaderAt interno
func readEhdrDirect(elfFile *elf.File) (*Ehdr, error) {
	// Usa unsafe pointer per accesso diretto più efficiente
	fileValue := reflect.ValueOf(elfFile).Elem()
	readerField := fileValue.FieldByName("r")

	if !readerField.IsValid() || readerField.IsNil() {
		return nil, fmt.Errorf("cannot access internal reader")
	}

	readerAt := (*io.ReaderAt)(unsafe.Pointer(readerField.UnsafeAddr()))
	return parseHeaderFromReader(*readerAt, elfFile.Class, elfFile.Data)
}

// readEhdrSafe usa solo API pubbliche (metodo di fallback)
func readEhdrSafe(elfFile *elf.File) (*Ehdr, error) {
	header := &elfFile.FileHeader

	ehdr := &Ehdr{
		Class:   elfFile.Class,
		Data:    elfFile.Data,
		Type:    header.Type,
		Machine: header.Machine,
		Version: uint32(header.Version),
		Entry:   header.Entry,
		Phnum:   uint16(len(elfFile.Progs)),
		Shnum:   uint16(len(elfFile.Sections)),
	}

	// Costruisce identificatore ELF
	ehdr.Ident = [16]byte{
		0x7F, 'E', 'L', 'F',
		byte(elfFile.Class), byte(elfFile.Data), byte(header.Version),
		byte(header.OSABI), header.ABIVersion,
		0, 0, 0, 0, 0, 0, 0, // padding
	}

	// Imposta dimensioni specifiche per architettura
	if elfFile.Class == elf.ELFCLASS32 {
		ehdr.Ehsize = elf32HeaderSize
		ehdr.Phentsize = 32
		ehdr.Shentsize = 40
	} else {
		ehdr.Ehsize = elf64HeaderSize
		ehdr.Phentsize = 56
		ehdr.Shentsize = 64
	}

	return ehdr, nil
}

// parseHeaderFromReader decodifica l'header completo da ReaderAt
func parseHeaderFromReader(r io.ReaderAt, class elf.Class, data elf.Data) (*Ehdr, error) {
	var headerSize int64
	if class == elf.ELFCLASS32 {
		headerSize = elf32HeaderSize
	} else {
		headerSize = elf64HeaderSize
	}

	buf := make([]byte, headerSize)
	if _, err := r.ReadAt(buf, 0); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReadError, err)
	}

	var byteOrder binary.ByteOrder
	switch data {
	case elf.ELFDATA2LSB:
		byteOrder = binary.LittleEndian
	case elf.ELFDATA2MSB:
		byteOrder = binary.BigEndian
	default:
		return nil, fmt.Errorf("%w: unsupported data encoding %v", ErrUnsupportedType, data)
	}

	return decodeHeader(buf, class, data, byteOrder)
}

// decodeHeader decodifica i byte dell'header in struct Ehdr
func decodeHeader(buf []byte, class elf.Class, data elf.Data, bo binary.ByteOrder) (*Ehdr, error) {
	if len(buf) < elfIdentSize {
		return nil, ErrReadError
	}

	ehdr := &Ehdr{
		Class: class,
		Data:  data,
	}

	copy(ehdr.Ident[:], buf[:elfIdentSize])
	reader := bytes.NewReader(buf[elfIdentSize:])

	// Decodifica campi comuni
	commonFields := []interface{}{
		&ehdr.Type, &ehdr.Machine, &ehdr.Version,
	}

	for _, field := range commonFields {
		if err := binary.Read(reader, bo, field); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrReadError, err)
		}
	}

	// Decodifica campi specifici per architettura
	if class == elf.ELFCLASS32 {
		if err := decode32Fields(reader, bo, ehdr); err != nil {
			return nil, err
		}
	} else {
		if err := decode64Fields(reader, bo, ehdr); err != nil {
			return nil, err
		}
	}

	// Decodifica campi finali
	finalFields := []interface{}{
		&ehdr.Flags, &ehdr.Ehsize, &ehdr.Phentsize,
		&ehdr.Phnum, &ehdr.Shentsize, &ehdr.Shnum, &ehdr.Shstrndx,
	}

	for _, field := range finalFields {
		if err := binary.Read(reader, bo, field); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrReadError, err)
		}
	}

	return ehdr, nil
}

// decode32Fields decodifica campi specifici ELF32
func decode32Fields(reader *bytes.Reader, bo binary.ByteOrder, ehdr *Ehdr) error {
	var entry, phoff, shoff uint32

	fields := []interface{}{&entry, &phoff, &shoff}
	for _, field := range fields {
		if err := binary.Read(reader, bo, field); err != nil {
			return fmt.Errorf("%w: %v", ErrReadError, err)
		}
	}

	ehdr.Entry = uint64(entry)
	ehdr.Phoff = uint64(phoff)
	ehdr.Shoff = uint64(shoff)

	return nil
}

// decode64Fields decodifica campi specifici ELF64
func decode64Fields(reader *bytes.Reader, bo binary.ByteOrder, ehdr *Ehdr) error {
	fields := []interface{}{&ehdr.Entry, &ehdr.Phoff, &ehdr.Shoff}

	for _, field := range fields {
		if err := binary.Read(reader, bo, field); err != nil {
			return fmt.Errorf("%w: %v", ErrReadError, err)
		}
	}

	return nil
}

// ReadPhdrs legge i program headers
func ReadPhdrs(elfFile *elf.File) ([]*Phdr, error) {
	if elfFile == nil {
		return nil, ErrInvalidELF
	}

	if len(elfFile.Progs) == 0 {
		return []*Phdr{}, nil
	}

	phdrs := make([]*Phdr, 0, len(elfFile.Progs))

	for _, prog := range elfFile.Progs {
		if prog == nil {
			continue // Skip nil entries instead of failing
		}

		phdrs = append(phdrs, &Phdr{
			Type:   prog.Type,
			Flags:  prog.Flags,
			Off:    prog.Off,
			Vaddr:  prog.Vaddr,
			Paddr:  prog.Paddr,
			Filesz: prog.Filesz,
			Memsz:  prog.Memsz,
			Align:  prog.Align,
		})
	}

	return phdrs, nil
}

// ReadELFInfo legge header e program headers in una operazione
func ReadELFInfo(elfFile *elf.File) (*ELFInfo, error) {
	if elfFile == nil {
		return nil, ErrInvalidELF
	}

	ehdr, err := ReadEhdr(elfFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ELF header: %w", err)
	}

	phdrs, err := ReadPhdrs(elfFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read program headers: %w", err)
	}

	return &ELFInfo{
		Header: ehdr,
		Class:  ehdr.Class,
		Data:   ehdr.Data,
		Phdrs:  phdrs,
	}, nil
}

// ReadEhdrFromReaderAt legge direttamente da ReaderAt (funzione di utilità)
func ReadEhdrFromReaderAt(r io.ReaderAt, class elf.Class, data elf.Data) (*Ehdr, error) {
	if r == nil {
		return nil, ErrInvalidELF
	}

	return parseHeaderFromReader(r, class, data)
}
