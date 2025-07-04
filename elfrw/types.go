package elfrw

import (
	"fmt"
	"github.com/yalue/elf_reader"
	"gosstrip/common"
	"os"
)

type ELFFile struct {
	File             *os.File
	ELF              elf_reader.ELFFile
	Is64Bit          bool
	FileName         string
	Sections         []Section
	RawData          []byte
	entryPoint       uint64
	machineType      string
	hasInterpreter   bool
	isDynamic        bool
	Segments         []Segment
	Symbols          []Symbol
	DynamicEntries   []DynamicEntry
	nameOffsets      map[string]uint32
	usedFallbackMode bool
	common.CommonFileInfo
}

type ELFOffsets struct {
	ELFHeaderSize        int64
	SectionHeadersOffset int64
	ProgramHeadersOffset int64
	NumberOfSections     int
	NumberOfSegments     int
}

type Section struct {
	Name      string
	Offset    int64
	Size      int64
	Address   uint64
	Index     int
	Type      uint32
	Flags     uint64
	Link      uint32
	Info      uint32
	Alignment uint64
	IsAlloc   bool
	common.CommonSectionInfo
}

type Segment struct {
	Type         uint32
	Flags        uint32
	Offset       uint64
	VirtualAddr  uint64
	PhysicalAddr uint64
	FileSize     uint64
	MemSize      uint64
	Alignment    uint64
	IsExecutable bool
	IsReadable   bool
	IsWritable   bool
	Loadable     bool
	Index        uint16
}

type SectionInfo struct {
	Name   string
	Offset int64
	Size   int64
	common.CommonSectionInfo
}

type Symbol struct {
	Name    string
	Value   uint64
	Size    uint64
	Type    uint8
	Binding uint8
	Section uint16
}

type DynamicEntry struct {
	Tag   int64
	Value uint64
}

const (
	// ELF magic number and identification
	ELF_MAG0       = 0x7f // ELF magic number byte 0
	ELF_MAG1       = 'E'  // ELF magic number byte 1
	ELF_MAG2       = 'L'  // ELF magic number byte 2
	ELF_MAG3       = 'F'  // ELF magic number byte 3
	ELF_MAG_SIZE   = 4    // Size of ELF magic number
	ELF_IDENT_SIZE = 16   // Size of ELF identification array
)

// ELF header field positions - consolidated and cleaned up
const (
	// ELF64 header offsets
	ELF64_E_ENTRY     = 24 // Entry point address
	ELF64_E_PHOFF     = 32 // Program header table offset
	ELF64_E_SHOFF     = 40 // Section header table offset
	ELF64_E_FLAGS     = 48 // Processor-specific flags
	ELF64_E_PHENTSIZE = 54 // Program header entry size
	ELF64_E_SHENTSIZE = 58 // Section header entry size
	ELF64_E_SHNUM     = 60 // Number of section headers
	ELF64_E_SHSTRNDX  = 62 // Section header string table index
	// ELF32 header offsets
	ELF32_E_ENTRY     = 24 // Entry point address
	ELF32_E_PHOFF     = 28 // Program header table offset
	ELF32_E_SHOFF     = 32 // Section header table offset
	ELF32_E_FLAGS     = 36 // Processor-specific flags
	ELF32_E_PHENTSIZE = 42 // Program header entry size
	ELF32_E_SHENTSIZE = 46 // Section header entry size
	ELF32_E_SHNUM     = 48 // Number of section headers
	ELF32_E_SHSTRNDX  = 50 // Section header string table index
)

const (
	// Section header types
	SHT_NULL        = 0
	SHT_PROGBITS    = 1
	SHT_SYMTAB      = 2
	SHT_STRTAB      = 3
	SHT_RELA        = 4
	SHT_HASH        = 5
	SHT_DYNAMIC     = 6
	SHT_NOTE        = 7
	SHT_NOBITS      = 8
	SHT_REL         = 9
	SHT_SHLIB       = 10
	SHT_DYNSYM      = 11
	SHT_GNU_HASH    = 0x6ffffff6
	SHT_GNU_VERDEF  = 0x6ffffffd
	SHT_GNU_VERNEED = 0x6ffffffe
	SHT_GNU_VERSYM  = 0x6fffffff
)

const (
	// Section header flags
	SHF_WRITE     = 0x1
	SHF_ALLOC     = 0x2
	SHF_EXECINSTR = 0x4
	SHF_STRINGS   = 0x20
)

const (
	// Program header types
	PT_NULL    = 0
	PT_LOAD    = 1
	PT_DYNAMIC = 2
	PT_INTERP  = 3
	PT_NOTE    = 4
	PT_SHLIB   = 5
	PT_PHDR    = 6
	PT_TLS     = 7
)

const (
	// ELF file types
	ET_NONE = 0 // No file type
	ET_REL  = 1 // Relocatable file
	ET_EXEC = 2 // Executable file
	ET_DYN  = 3 // Shared object file
	ET_CORE = 4 // Core file
)

const (
	// Symbol table entry sizes
	ELF32_SYM_SIZE = 16 // sizeof(Elf32_Sym)
	ELF64_SYM_SIZE = 24 // sizeof(Elf64_Sym)
)

const (
	// Symbol binding types
	STB_LOCAL  = 0 // Local symbols
	STB_GLOBAL = 1 // Global symbols
	STB_WEAK   = 2 // Weak symbols
)

const (
	// Symbol types
	STT_NOTYPE  = 0 // Symbol type is not specified
	STT_OBJECT  = 1 // Symbol is a data object
	STT_FUNC    = 2 // Symbol is a code object (function)
	STT_SECTION = 3 // Symbol associated with a section
	STT_FILE    = 4 // Symbol's name is file name
)

const (
	// Dynamic table tags
	DT_NULL     = 0 // Marks end of dynamic section
	DT_NEEDED   = 1 // Name of needed library
	DT_PLTRELSZ = 2 // Size in bytes of PLT relocs
	DT_PLTGOT   = 3 // Processor defined value
	DT_HASH     = 4 // Address of symbol hash table
	DT_STRTAB   = 5 // Address of string table
	DT_SYMTAB   = 6 // Address of symbol table
)

const (
	// Special GNU program header types for security
	PT_GNU_STACK = 0x6474e551 // Indicates stack executability
	PT_GNU_RELRO = 0x6474e552 // Read-only after relocation
)

const (
	// Header sizes
	ELF32_EHDR_SIZE = 52
	ELF64_EHDR_SIZE = 64
	ELF32_SHDR_SIZE = 40
	ELF64_SHDR_SIZE = 64
)

const (
	// Program/Section header field offsets and sizes
	ELF64_P_OFFSET = 8
	ELF64_P_FILESZ = 32
	ELF32_P_OFFSET = 4
	ELF32_P_FILESZ = 16

	// Program header field offsets
	ELF64_P_VADDR = 16 // Virtual address offset in 64-bit program header
	ELF64_P_PADDR = 24 // Physical address offset in 64-bit program header
	ELF32_P_VADDR = 8  // Virtual address offset in 32-bit program header
	ELF32_P_PADDR = 12 // Physical address offset in 32-bit program header

	ELF64_S_OFFSET = 24
	ELF64_S_SIZE   = 32
	ELF32_S_OFFSET = 16
	ELF32_S_SIZE   = 20

	// Section header field offsets
	ELF_SH_NAME        = 0  // Section name offset
	ELF_SH_TYPE        = 4  // Section type
	ELF32_SH_FLAGS     = 8  // Section flags (32-bit)
	ELF32_SH_ADDR      = 12 // Section virtual address (32-bit)
	ELF32_SH_LINK      = 24 // Section link (32-bit)
	ELF32_SH_INFO      = 28 // Section info (32-bit)
	ELF32_SH_ADDRALIGN = 32 // Section alignment (32-bit)
	ELF64_SH_FLAGS     = 8  // Section flags (64-bit)
	ELF64_SH_ADDR      = 16 // Section virtual address (64-bit)
	ELF64_SH_LINK      = 40 // Section link (64-bit)
	ELF64_SH_INFO      = 44 // Section info (64-bit)
	ELF64_SH_ADDRALIGN = 48 // Section alignment (64-bit)

	// Dynamic entry sizes and offsets
	ELF32_DYN_SIZE = 8  // 32-bit dynamic entry size (4 bytes tag + 4 bytes value)
	ELF64_DYN_SIZE = 16 // 64-bit dynamic entry size (8 bytes tag + 8 bytes value)
	ELF32_DYN_VAL  = 4  // Offset to value field in 32-bit dynamic entry
	ELF64_DYN_VAL  = 8  // Offset to value field in 64-bit dynamic entry
)

func getSectionTypeName(sectionType uint32) string {
	switch sectionType {
	case SHT_NULL:
		return "NULL"
	case SHT_PROGBITS:
		return "PROGBITS"
	case SHT_SYMTAB:
		return "SYMTAB"
	case SHT_STRTAB:
		return "STRTAB"
	case SHT_RELA:
		return "RELA"
	case SHT_HASH:
		return "HASH"
	case SHT_DYNAMIC:
		return "DYNAMIC"
	case SHT_NOTE:
		return "NOTE"
	case SHT_NOBITS:
		return "NOBITS"
	case SHT_REL:
		return "REL"
	case SHT_SHLIB:
		return "SHLIB"
	case SHT_DYNSYM:
		return "DYNSYM"
	default:
		return fmt.Sprintf("UNK_%X", sectionType)
	}
}

func getDynamicTagName(tag int64) string {
	switch tag {
	case DT_NULL:
		return "DT_NULL"
	case DT_NEEDED:
		return "DT_NEEDED"
	case DT_PLTRELSZ:
		return "DT_PLTRELSZ"
	case DT_PLTGOT:
		return "DT_PLTGOT"
	case DT_HASH:
		return "DT_HASH"
	case DT_STRTAB:
		return "DT_STRTAB"
	case DT_SYMTAB:
		return "DT_SYMTAB"
	default:
		return fmt.Sprintf("DT_UNKNOWN_%X", tag)
	}
}
