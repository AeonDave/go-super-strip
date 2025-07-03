package elfrw

import (
	"os"

	"github.com/yalue/elf_reader"
)

type ELFFile struct {
	File     *os.File
	ELF      elf_reader.ELFFile
	Is64Bit  bool
	FileName string
	Sections []Section
	RawData  []byte

	entryPoint     uint64
	machineType    string
	hasInterpreter bool
	isDynamic      bool

	FileSize      int64
	IsPacked      bool
	HasOverlay    bool
	OverlayOffset int64
	OverlaySize   int64

	Segments       []Segment
	Symbols        []Symbol
	DynamicEntries []DynamicEntry

	versionInfo      map[string]string
	nameOffsets      map[string]uint32 // Cache for section name offsets
	usedFallbackMode bool              // Track if fallback mode was used
}

type ELFOffsets struct {
	ELFHeaderSize        int64
	SectionHeadersOffset int64
	ProgramHeadersOffset int64
	NumberOfSections     int
	NumberOfSegments     int
}

type Section struct {
	Name         string
	Offset       int64
	Size         int64
	Address      uint64
	Index        int
	Type         uint32
	Flags        uint64
	Entropy      float64
	MD5Hash      string
	SHA1Hash     string
	SHA256Hash   string
	IsExecutable bool
	IsReadable   bool
	IsWritable   bool
	IsAlloc      bool
	Link         uint32
	Info         uint32
	Alignment    uint64
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

type ParseMode int

type ParseResult struct {
	Mode     ParseMode
	Success  bool
	Reason   string
	Warnings []string
}

type ELFFileMode struct {
	usedFallbackMode bool
}

// ELF constants
const (
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
	SHF_WRITE     = 0x1
	SHF_ALLOC     = 0x2
	SHF_EXECINSTR = 0x4
	SHF_STRINGS   = 0x20
)

const (
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
	PF_X = 0x1 // Execute
	PF_W = 0x2 // Write
	PF_R = 0x4 // Read
)

const (
	STB_LOCAL  = 0
	STB_GLOBAL = 1
	STB_WEAK   = 2
)

const (
	STT_NOTYPE  = 0
	STT_OBJECT  = 1
	STT_FUNC    = 2
	STT_SECTION = 3
	STT_FILE    = 4
)

const (
	// Offset per ELF64 header fields
	elf64E_phoff_offset     = 32
	elf64E_shoff_offset     = 40
	elf64E_phentsize_offset = 54
	elf64E_shentsize_offset = 58
	elf64E_shnum_offset     = 60
	elf64E_shstrndx_offset  = 62

	// Offset per ELF32 header fields
	elf32E_phoff_offset     = 28
	elf32E_shoff_offset     = 32
	elf32E_phentsize_offset = 42
	elf32E_shentsize_offset = 46
	elf32E_shnum_offset     = 48
	elf32E_shstrndx_offset  = 50

	// Offsets and sizes for program headers
	elf64P_offset = 8
	elf64P_filesz = 32
	elf32P_offset = 4
	elf32P_filesz = 16

	// Offsets and sizes for section headers
	elf64S_offset = 24
	elf64S_size   = 32
	elf32S_offset = 16
	elf32S_size   = 20
)
