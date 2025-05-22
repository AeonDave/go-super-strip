package elfrw

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

// ReadEhdr reads the ELF header from an *elf.File and populates a custom Ehdr struct.
func ReadEhdr(elfFile *elf.File) (*Ehdr, elf.Class, elf.Data, error) {
	if elfFile == nil {
		return nil, 0, 0, fmt.Errorf("invalid ELF file")
	}

	// Prova ad ottenere il ReaderAt usando reflection (RISCHIOSO)
	fValue := reflect.ValueOf(elfFile).Elem()
	raField := fValue.FieldByName("r")
	if !raField.IsValid() {
		// Fallback alla versione sicura se la reflection fallisce
		return ReadEhdr(elfFile)
	}

	readerAt, ok := raField.Interface().(io.ReaderAt)
	if !ok {
		return ReadEhdr(elfFile) // Fallback
	}

	// Determina dimensione header
	class := elfFile.Class
	hdrSize := 52 // ELF32
	if class == elf.ELFCLASS64 {
		hdrSize = 64
	}

	// Leggi l'intero header
	hdr := make([]byte, hdrSize)
	if _, err := readerAt.ReadAt(hdr, 0); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read ELF header: %w", err)
	}

	// Parsea l'header
	ehdr := &Ehdr{}
	copy(ehdr.Ident[:], hdr[:16])

	// Usa il ByteOrder già determinato da debug/elf
	bo := elfFile.ByteOrder
	buf := bytes.NewReader(hdr[16:]) // Salta l'identificatore

	// Decodifica i campi comuni con controllo errori
	if err := binary.Read(buf, bo, &ehdr.Type); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read Type: %w", err)
	}
	if err := binary.Read(buf, bo, &ehdr.Machine); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read Machine: %w", err)
	}
	if err := binary.Read(buf, bo, &ehdr.Version); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read Version: %w", err)
	}

	// Decodifica campi specifici per 32/64 bit
	if class == elf.ELFCLASS32 {
		var entry, phoff, shoff uint32
		if err := binary.Read(buf, bo, &entry); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to read Entry: %w", err)
		}
		if err := binary.Read(buf, bo, &phoff); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to read Phoff: %w", err)
		}
		if err := binary.Read(buf, bo, &shoff); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to read Shoff: %w", err)
		}
		ehdr.Entry = uint64(entry)
		ehdr.Phoff = uint64(phoff)
		ehdr.Shoff = uint64(shoff)
	} else {
		if err := binary.Read(buf, bo, &ehdr.Entry); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to read Entry: %w", err)
		}
		if err := binary.Read(buf, bo, &ehdr.Phoff); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to read Phoff: %w", err)
		}
		if err := binary.Read(buf, bo, &ehdr.Shoff); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to read Shoff: %w", err)
		}
	}

	// Decodifica i campi rimanenti con controllo errori
	fields := []interface{}{
		&ehdr.Flags, &ehdr.Ehsize, &ehdr.Phentsize,
		&ehdr.Phnum, &ehdr.Shentsize, &ehdr.Shnum, &ehdr.Shstrndx,
	}

	for i, field := range fields {
		if err := binary.Read(buf, bo, field); err != nil {
			return nil, 0, 0, fmt.Errorf("failed to read field %d: %w", i, err)
		}
	}

	return ehdr, elfFile.Class, elfFile.Data, nil
}

// ReadPhdrs reads the program headers from an *elf.File and populates a slice of custom Phdr structs.
func ReadPhdrs(elfFile *elf.File) ([]*Phdr, error) {
	if elfFile == nil {
		return nil, fmt.Errorf("invalid ELF file")
	}

	if len(elfFile.Progs) == 0 {
		return []*Phdr{}, nil // Restituisce slice vuota invece di nil
	}

	phdrs := make([]*Phdr, len(elfFile.Progs))

	for i, prog := range elfFile.Progs {
		phdrs[i] = &Phdr{
			Type:   uint32(prog.Type),
			Flags:  uint32(prog.Flags),
			Off:    prog.Off,
			Vaddr:  prog.Vaddr,
			Paddr:  prog.Paddr,
			Filesz: prog.Filesz,
			Memsz:  prog.Memsz,
			Align:  prog.Align,
		}
	}

	return phdrs, nil
}

func ReadELFInfo(elfFile *elf.File) (*ELFInfo, error) {
	if elfFile == nil {
		return nil, fmt.Errorf("invalid ELF file")
	}

	ehdr, class, data, err := ReadEhdr(elfFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ELF header: %w", err)
	}

	phdrs, err := ReadPhdrs(elfFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read program headers: %w", err)
	}

	return &ELFInfo{
		Header: ehdr,
		Class:  class,
		Data:   data,
		Phdrs:  phdrs,
	}, nil
}

func ValidateELF(elfFile *elf.File) error {
	if elfFile == nil {
		return fmt.Errorf("invalid ELF file")
	}
	// Verifica classe ELF (32-bit o 64-bit)
	if elfFile.Class != elf.ELFCLASS32 && elfFile.Class != elf.ELFCLASS64 {
		return fmt.Errorf("unsupported ELF class: %v", elfFile.Class)
	}

	// Verifica endianness
	if elfFile.Data != elf.ELFDATA2LSB && elfFile.Data != elf.ELFDATA2MSB {
		return fmt.Errorf("unsupported ELF data encoding: %v", elfFile.Data)
	}

	return nil
}

func GetArchitectureName(machine elf.Machine) string {
	switch machine {
	case elf.EM_386:
		return "Intel 80386"
	case elf.EM_X86_64:
		return "AMD x86-64"
	case elf.EM_ARM:
		return "ARM"
	case elf.EM_AARCH64:
		return "AArch64"
	case elf.EM_RISCV:
		return "RISC-V"
	case elf.EM_PPC:
		return "PowerPC"
	case elf.EM_PPC64:
		return "PowerPC64"
	case elf.EM_MIPS:
		return "MIPS"
	case elf.EM_S390:
		return "IBM System/390"
	default:
		return fmt.Sprintf("Unknown (%d)", machine)
	}
}
