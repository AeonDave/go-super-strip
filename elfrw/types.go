package elfrw

import (
	"debug/elf"
	"fmt"
)

// Ehdr32 ELF Type-Specific Headers
type Ehdr32 struct {
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint32
	Phoff     uint32
	Shoff     uint32
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

// Ehdr64 ELF Type-Specific Headers
type Ehdr64 struct {
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

// Ehdr Unified ELF Header
type Ehdr struct {
	Class     elf.Class
	Data      elf.Data
	Ident     [16]byte
	Type      elf.Type
	Machine   elf.Machine
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

// Phdr Program Header
type Phdr struct {
	Type   elf.ProgType
	Flags  elf.ProgFlag
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// ELFInfo ELF Metadata Container
type ELFInfo struct {
	Header *Ehdr
	Class  elf.Class
	Data   elf.Data
	Phdrs  []*Phdr
}

func (e *Ehdr) String() string {
	return fmt.Sprintf("ELF Header [%s-%s]:\n"+
		"Type: %s\nMachine: %s\nVersion: %d\nEntry: 0x%x\n"+
		"Program Headers: %d @ 0x%x\nSection Headers: %d @ 0x%x",
		e.Class, e.Data,
		e.Type, e.Machine, e.Version, e.Entry,
		e.Phnum, e.Phoff, e.Shnum, e.Shoff)
}

func (p *Phdr) String() string {
	return fmt.Sprintf("PHDR: %s (%s)\n"+
		"Offset: 0x%x-0x%x\nVirtual: 0x%x-0x%x\nAlign: %d",
		p.Type, p.Flags,
		p.Off, p.Off+p.Filesz,
		p.Vaddr, p.Vaddr+p.Memsz,
		p.Align)
}
