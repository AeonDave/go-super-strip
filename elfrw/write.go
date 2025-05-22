package elfrw

import (
	"debug/elf"
	"encoding/binary"
	"fmt" // For error messages
	"io"
)

// WriteEhdr writes the custom Ehdr struct to an io.Writer in ELF format.
func WriteEhdr(w io.Writer, ehdr *Ehdr, class elf.Class, data elf.Data) error {
	var byteOrder binary.ByteOrder
	switch data {
	case elf.ELFDATA2LSB:
		byteOrder = binary.LittleEndian
	case elf.ELFDATA2MSB:
		byteOrder = binary.BigEndian
	default:
		return fmt.Errorf("unknown elf data encoding: %v", data)
	}

	// Write Ident
	if err := binary.Write(w, byteOrder, ehdr.Ident); err != nil {
		return fmt.Errorf("failed to write ELF ident: %w", err)
	}

	switch class {
	case elf.ELFCLASS64:
		if err := binary.Write(w, byteOrder, ehdr.Type); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Machine); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Version); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Entry); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Phoff); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Shoff); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Flags); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Ehsize); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Phentsize); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Phnum); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Shentsize); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Shnum); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Shstrndx); err != nil {
			return err
		}
	case elf.ELFCLASS32:
		if err := binary.Write(w, byteOrder, ehdr.Type); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Machine); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Version); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, uint32(ehdr.Entry)); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, uint32(ehdr.Phoff)); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, uint32(ehdr.Shoff)); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Flags); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Ehsize); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Phentsize); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Phnum); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Shentsize); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Shnum); err != nil {
			return err
		}
		if err := binary.Write(w, byteOrder, ehdr.Shstrndx); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown elf class: %v", class)
	}

	return nil
}

// WritePhdrs writes the custom Phdr structs to an io.Writer in ELF format.
func WritePhdrs(w io.Writer, phdrs []*Phdr, class elf.Class, data elf.Data) error {
	var byteOrder binary.ByteOrder
	switch data {
	case elf.ELFDATA2LSB:
		byteOrder = binary.LittleEndian
	case elf.ELFDATA2MSB:
		byteOrder = binary.BigEndian
	default:
		return fmt.Errorf("unknown elf data encoding: %v", data)
	}

	for _, phdr := range phdrs {
		switch class {
		case elf.ELFCLASS64:
			if err := binary.Write(w, byteOrder, phdr.Type); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, phdr.Flags); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, phdr.Off); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, phdr.Vaddr); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, phdr.Paddr); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, phdr.Filesz); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, phdr.Memsz); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, phdr.Align); err != nil {
				return err
			}
		case elf.ELFCLASS32:
			if err := binary.Write(w, byteOrder, phdr.Type); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, phdr.Flags); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, uint32(phdr.Off)); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, uint32(phdr.Vaddr)); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, uint32(phdr.Paddr)); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, uint32(phdr.Filesz)); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, uint32(phdr.Memsz)); err != nil {
				return err
			}
			if err := binary.Write(w, byteOrder, uint32(phdr.Align)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown elf class: %v", class)
		}
	}
	return nil
}
