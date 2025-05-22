package elfrw

import (
	"debug/elf"
	"fmt"
)

type Ehdr struct {
	Ident     [16]byte // ELF identification
	Type      uint16   // Object file type
	Machine   uint16   // Architecture
	Version   uint32   // Object file version
	Entry     uint64   // Entry point virtual address
	Phoff     uint64   // Program header table file offset
	Shoff     uint64   // Section header table file offset
	Flags     uint32   // Processor-specific flags
	Ehsize    uint16   // ELF header size in bytes
	Phentsize uint16   // Program header table entry size
	Phnum     uint16   // Program header table entry count
	Shentsize uint16   // Section header table entry size
	Shnum     uint16   // Section header table entry count
	Shstrndx  uint16   // Section header string table index
}

type Phdr struct {
	Type   uint32 // Segment type
	Flags  uint32 // Segment flags
	Off    uint64 // Segment file offset
	Vaddr  uint64 // Segment virtual address
	Paddr  uint64 // Segment physical address
	Filesz uint64 // Segment size in file
	Memsz  uint64 // Segment size in memory
	Align  uint64 // Segment alignment
}

type ELFInfo struct {
	Header *Ehdr
	Class  elf.Class
	Data   elf.Data
	Phdrs  []*Phdr
}

// String implementa l'interfaccia Stringer per Ehdr
func (e *Ehdr) String() string {
	return fmt.Sprintf("ELF Header:\n"+
		"  Type: %d, Machine: %d, Version: %d\n"+
		"  Entry: 0x%x, Phoff: 0x%x, Shoff: 0x%x\n"+
		"  Flags: 0x%x, Ehsize: %d\n"+
		"  Phnum: %d, Shnum: %d",
		e.Type, e.Machine, e.Version,
		e.Entry, e.Phoff, e.Shoff,
		e.Flags, e.Ehsize,
		e.Phnum, e.Shnum)
}

// String implementa l'interfaccia Stringer per Phdr
func (p *Phdr) String() string {
	return fmt.Sprintf("Program Header:\n"+
		"  Type: %d, Flags: 0x%x\n"+
		"  Off: 0x%x, Vaddr: 0x%x, Paddr: 0x%x\n"+
		"  Filesz: %d, Memsz: %d, Align: %d",
		p.Type, p.Flags,
		p.Off, p.Vaddr, p.Paddr,
		p.Filesz, p.Memsz, p.Align)
}
