package elfrw

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidWriter = errors.New("invalid writer")
	ErrWriteError    = errors.New("failed to write ELF data")
)

// WriteEhdr scrive l'header ELF nel formato corretto
func WriteEhdr(w io.Writer, ehdr *Ehdr, class elf.Class, data elf.Data) error {
	if w == nil || ehdr == nil {
		return ErrInvalidWriter
	}

	byteOrder, err := getByteOrder(data)
	if err != nil {
		return err
	}

	// Scrive l'identificatore ELF (sempre 16 bytes)
	if err := binary.Write(w, byteOrder, ehdr.Ident); err != nil {
		return fmt.Errorf("%w: failed to write ELF ident: %v", ErrWriteError, err)
	}

	// Usa un buffer per ottimizzare le scritture multiple
	var buf bytes.Buffer

	switch class {
	case elf.ELFCLASS32:
		err = writeEhdr32Fields(&buf, ehdr, byteOrder)
	case elf.ELFCLASS64:
		err = writeEhdr64Fields(&buf, ehdr, byteOrder)
	default:
		return fmt.Errorf("unsupported ELF class: %v", class)
	}

	if err != nil {
		return err
	}

	// Scrive tutto il buffer in una sola operazione
	_, err = w.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWriteError, err)
	}

	return nil
}

// writeEhdr32Fields scrive i campi dell'header ELF32
func writeEhdr32Fields(buf *bytes.Buffer, ehdr *Ehdr, bo binary.ByteOrder) error {
	// Slice di campi da scrivere in ordine per ELF32
	fields := []interface{}{
		ehdr.Type,
		ehdr.Machine,
		ehdr.Version,
		uint32(ehdr.Entry), // Cast a 32-bit
		uint32(ehdr.Phoff), // Cast a 32-bit
		uint32(ehdr.Shoff), // Cast a 32-bit
		ehdr.Flags,
		ehdr.Ehsize,
		ehdr.Phentsize,
		ehdr.Phnum,
		ehdr.Shentsize,
		ehdr.Shnum,
		ehdr.Shstrndx,
	}

	return writeFields(buf, fields, bo)
}

// writeEhdr64Fields scrive i campi dell'header ELF64
func writeEhdr64Fields(buf *bytes.Buffer, ehdr *Ehdr, bo binary.ByteOrder) error {
	// Slice di campi da scrivere in ordine per ELF64
	fields := []interface{}{
		ehdr.Type,
		ehdr.Machine,
		ehdr.Version,
		ehdr.Entry, // Mantiene 64-bit
		ehdr.Phoff, // Mantiene 64-bit
		ehdr.Shoff, // Mantiene 64-bit
		ehdr.Flags,
		ehdr.Ehsize,
		ehdr.Phentsize,
		ehdr.Phnum,
		ehdr.Shentsize,
		ehdr.Shnum,
		ehdr.Shstrndx,
	}

	return writeFields(buf, fields, bo)
}

// WritePhdrs scrive i program headers nel formato corretto
func WritePhdrs(w io.Writer, phdrs []*Phdr, class elf.Class, data elf.Data) error {
	if w == nil {
		return ErrInvalidWriter
	}

	if len(phdrs) == 0 {
		return nil // Niente da scrivere
	}

	byteOrder, err := getByteOrder(data)
	if err != nil {
		return err
	}

	// Usa un buffer per ottimizzare le scritture
	var buf bytes.Buffer

	for i, phdr := range phdrs {
		if phdr == nil {
			return fmt.Errorf("program header %d is nil", i)
		}

		switch class {
		case elf.ELFCLASS32:
			err = writePhdr32Fields(&buf, phdr, byteOrder)
		case elf.ELFCLASS64:
			err = writePhdr64Fields(&buf, phdr, byteOrder)
		default:
			return fmt.Errorf("unsupported ELF class: %v", class)
		}

		if err != nil {
			return fmt.Errorf("failed to write program header %d: %w", i, err)
		}
	}

	// Scrive tutto in una operazione
	_, err = w.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWriteError, err)
	}

	return nil
}

// writePhdr32Fields scrive i campi del program header ELF32
func writePhdr32Fields(buf *bytes.Buffer, phdr *Phdr, bo binary.ByteOrder) error {
	fields := []interface{}{
		phdr.Type,
		uint32(phdr.Off),    // Cast a 32-bit
		uint32(phdr.Vaddr),  // Cast a 32-bit
		uint32(phdr.Paddr),  // Cast a 32-bit
		uint32(phdr.Filesz), // Cast a 32-bit
		uint32(phdr.Memsz),  // Cast a 32-bit
		phdr.Flags,          // In ELF32, flags viene dopo i campi di dimensione
		uint32(phdr.Align),  // Cast a 32-bit
	}

	return writeFields(buf, fields, bo)
}

// writePhdr64Fields scrive i campi del program header ELF64
func writePhdr64Fields(buf *bytes.Buffer, phdr *Phdr, bo binary.ByteOrder) error {
	fields := []interface{}{
		phdr.Type,
		phdr.Flags,  // In ELF64, flags viene subito dopo type
		phdr.Off,    // Mantiene 64-bit
		phdr.Vaddr,  // Mantiene 64-bit
		phdr.Paddr,  // Mantiene 64-bit
		phdr.Filesz, // Mantiene 64-bit
		phdr.Memsz,  // Mantiene 64-bit
		phdr.Align,  // Mantiene 64-bit
	}

	return writeFields(buf, fields, bo)
}

// WriteELFInfo scrive header e program headers completi
func WriteELFInfo(w io.Writer, info *ELFInfo) error {
	if w == nil || info == nil || info.Header == nil {
		return ErrInvalidWriter
	}

	// Scrive l'header
	if err := WriteEhdr(w, info.Header, info.Class, info.Data); err != nil {
		return fmt.Errorf("failed to write ELF header: %w", err)
	}

	// Scrive i program headers se presenti
	if len(info.Phdrs) > 0 {
		if err := WritePhdrs(w, info.Phdrs, info.Class, info.Data); err != nil {
			return fmt.Errorf("failed to write program headers: %w", err)
		}
	}

	return nil
}

// WriteELFToFile scrive un ELF completo includendo i dati dei segmenti
func WriteELFToFile(w io.Writer, info *ELFInfo, segmentData [][]byte) error {
	if w == nil || info == nil {
		return ErrInvalidWriter
	}

	// Calcola gli offset corretti per i program headers
	if err := calculateOffsets(info); err != nil {
		return fmt.Errorf("failed to calculate offsets: %w", err)
	}

	// Scrive header e program headers
	if err := WriteELFInfo(w, info); err != nil {
		return err
	}

	// Scrive i dati dei segmenti se forniti
	if len(segmentData) > 0 {
		if err := writeSegmentData(w, info.Phdrs, segmentData); err != nil {
			return fmt.Errorf("failed to write segment data: %w", err)
		}
	}

	return nil
}

// Funzioni di utilità

// getByteOrder determina l'ordine dei byte da elf.Data
func getByteOrder(data elf.Data) (binary.ByteOrder, error) {
	switch data {
	case elf.ELFDATA2LSB:
		return binary.LittleEndian, nil
	case elf.ELFDATA2MSB:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("unsupported ELF data encoding: %v", data)
	}
}

// writeFields scrive una slice di campi usando binary.Write
func writeFields(buf *bytes.Buffer, fields []interface{}, bo binary.ByteOrder) error {
	for i, field := range fields {
		if err := binary.Write(buf, bo, field); err != nil {
			return fmt.Errorf("failed to write field %d: %w", i, err)
		}
	}
	return nil
}

// calculateOffsets calcola e aggiorna gli offset dei program headers
func calculateOffsets(info *ELFInfo) error {
	if info.Header == nil {
		return errors.New("missing ELF header")
	}

	headerSize := uint64(info.Header.Ehsize)
	phdrSize := uint64(info.Header.Phentsize) * uint64(info.Header.Phnum)

	// Gli offset iniziano dopo l'header e tutti i program headers
	currentOffset := headerSize + phdrSize

	// Aggiorna l'offset dei program headers nell'header
	info.Header.Phoff = headerSize

	// Allinea ogni segmento secondo le sue specifiche
	for _, phdr := range info.Phdrs {
		if phdr.Align > 1 {
			// Allinea l'offset al boundary richiesto
			remainder := currentOffset % phdr.Align
			if remainder != 0 {
				currentOffset += phdr.Align - remainder
			}
		}

		phdr.Off = currentOffset
		currentOffset += phdr.Filesz
	}

	return nil
}

// writeSegmentData scrive i dati dei segmenti nei loro offset corretti
func writeSegmentData(w io.Writer, phdrs []*Phdr, segmentData [][]byte) error {
	if len(segmentData) != len(phdrs) {
		return fmt.Errorf("segment data count (%d) doesn't match program headers count (%d)",
			len(segmentData), len(phdrs))
	}

	// Crea un writer con seek se disponibile per gestire gli offset
	seeker, canSeek := w.(io.WriteSeeker)

	for i, data := range segmentData {
		if len(data) == 0 {
			continue // Skip empty segments
		}

		phdr := phdrs[i]

		// Se il writer supporta seek, posizionati all'offset corretto
		if canSeek {
			if _, err := seeker.Seek(int64(phdr.Off), io.SeekStart); err != nil {
				return fmt.Errorf("failed to seek to offset %d for segment %d: %w",
					phdr.Off, i, err)
			}
		}

		// Scrive i dati del segmento
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("failed to write segment %d data: %w", i, err)
		}
	}

	return nil
}

// ValidateWriteParams valida i parametri prima della scrittura
func ValidateWriteParams(ehdr *Ehdr, class elf.Class, data elf.Data) error {
	if ehdr == nil {
		return errors.New("ELF header is nil")
	}

	if class != elf.ELFCLASS32 && class != elf.ELFCLASS64 {
		return fmt.Errorf("invalid ELF class: %v", class)
	}

	if data != elf.ELFDATA2LSB && data != elf.ELFDATA2MSB {
		return fmt.Errorf("invalid ELF data encoding: %v", data)
	}

	// Verifica coerenza delle dimensioni
	expectedEhsize := uint16(elf32HeaderSize)
	expectedPhentsize := uint16(32)
	if class == elf.ELFCLASS64 {
		expectedEhsize = elf64HeaderSize
		expectedPhentsize = 56
	}

	if ehdr.Ehsize != expectedEhsize {
		return fmt.Errorf("invalid header size: expected %d, got %d",
			expectedEhsize, ehdr.Ehsize)
	}

	if ehdr.Phentsize != expectedPhentsize {
		return fmt.Errorf("invalid program header entry size: expected %d, got %d",
			expectedPhentsize, ehdr.Phentsize)
	}

	return nil
}
