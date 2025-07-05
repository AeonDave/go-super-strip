package perw

import (
	"debug/pe"
	"gosstrip/common"
	"os"
)

type PEFile struct {
	File               *os.File
	PE                 *pe.File
	Is64Bit            bool
	FileName           string
	Sections           []Section
	RawData            []byte
	imageBase          uint64
	entryPoint         uint32
	sizeOfImage        uint32
	sizeOfHeaders      uint32
	checksum           uint32
	subsystem          uint16
	dllCharacteristics uint16
	Machine            string
	TimeDateStamp      string
	directories        []DirectoryEntry
	Imports            []ImportInfo
	Exports            []ExportInfo
	SignatureOffset    int64
	signatureSize      int64
	PDBPath            string
	guidAge            string
	common.CommonFileInfo
}

type PEOffsets struct {
	ELfanew          int64
	OptionalHeader   int64
	FirstSectionHdr  int64
	NumberOfSections int
	OptionalHdrSize  int
}

type Section struct {
	Name                 string
	Offset               int64
	Size                 int64
	VirtualAddress       uint32
	VirtualSize          uint32
	Index                int
	Flags                uint32
	RVA                  uint32
	FileOffset           uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	common.CommonSectionInfo
}

type SectionInfo struct {
	Name         string
	FileOffset   int64
	Size         int64
	IsExecutable bool
	IsWritable   bool
}

type DirectoryEntry struct {
	Type uint16
	RVA  uint32
	Size uint32
}

type ImportInfo struct {
	LibraryName string
	DLL         string
	Functions   []string
	IatRva      uint32
}

type ExportInfo struct {
	Name      string
	Ordinal   uint16
	RVA       uint32
	Forwarder string
}

type ImportDescriptor struct {
	OriginalFirstThunk uint32 // RVA to original unbound IAT
	TimeDateStamp      uint32 // 0 if not bound, -1 if bound
	ForwarderChain     uint32 // -1 if no forwarders
	Name               uint32 // RVA of imported DLL name
	FirstThunk         uint32 // RVA to IAT (bound import table)
}

const (
	// PE magic signatures and identification
	PE_DOS_SIGNATURE   = 0x5A4D     // "MZ" - DOS header signature
	PE_NT_SIGNATURE    = 0x00004550 // "PE\0\0" - NT header signature
	PE_DOS_HEADER_SIZE = 64         // Size of DOS header
	PE_ELFANEW_OFFSET  = 60         // Offset to PE header pointer (e_lfanew)
)

const (
	// PE header offsets
	PE_SIGNATURE_OFFSET       = 0  // PE signature offset in NT header
	PE_FILE_HEADER_SIZE       = 20 // Size of COFF file header
	PE_MACHINE_OFFSET         = 4  // Machine type offset in file header
	PE_SECTIONS_OFFSET        = 6  // Number of sections offset
	PE_TIMESTAMP_OFFSET       = 8  // Timestamp offset
	PE_OPTSIZE_OFFSET         = 16 // Optional header size offset
	PE_CHARACTERISTICS_OFFSET = 18 // Characteristics offset
)

const (
	// Optional header offsets (32-bit)
	PE32_MAGIC               = 0x10b // PE32 magic number
	PE32_ENTRY_POINT         = 16    // Entry point RVA
	PE32_IMAGE_BASE          = 28    // Image base address
	PE32_SECTION_ALIGN       = 32    // Section alignment
	PE32_FILE_ALIGN          = 36    // File alignment
	PE32_SIZE_OF_IMAGE       = 56    // Size of image
	PE32_SIZE_OF_HEADERS     = 60    // Size of headers
	PE32_CHECKSUM            = 64    // Checksum
	PE32_SUBSYSTEM           = 68    // Subsystem
	PE32_DLL_CHARACTERISTICS = 70    // DLL characteristics
	PE32_DATA_DIRECTORIES    = 96    // Data directories start
)

const (
	// Optional header offsets (64-bit)
	PE64_MAGIC               = 0x20b // PE32+ magic number
	PE64_ENTRY_POINT         = 16    // Entry point RVA
	PE64_IMAGE_BASE          = 24    // Image base address
	PE64_SECTION_ALIGN       = 32    // Section alignment
	PE64_FILE_ALIGN          = 36    // File alignment
	PE64_SIZE_OF_IMAGE       = 56    // Size of image
	PE64_SIZE_OF_HEADERS     = 60    // Size of headers
	PE64_CHECKSUM            = 64    // Checksum
	PE64_SUBSYSTEM           = 68    // Subsystem
	PE64_DLL_CHARACTERISTICS = 70    // DLL characteristics
	PE64_DATA_DIRECTORIES    = 112   // Data directories start
)

const (
	// Section header offsets and sizes
	PE_SECTION_NAME_SIZE         = 8  // Section name size
	PE_SECTION_HEADER_SIZE       = 40 // Size of section header
	PE_SECTION_VIRTUAL_SIZE      = 8  // Virtual size offset
	PE_SECTION_VIRTUAL_ADDR      = 12 // Virtual address offset
	PE_SECTION_RAW_SIZE          = 16 // Raw data size offset
	PE_SECTION_RAW_OFFSET        = 20 // Raw data offset
	PE_SECTION_RELOC_OFFSET      = 24 // Relocations offset
	PE_SECTION_LINENUMBER_OFFSET = 28 // Line numbers offset
	PE_SECTION_RELOC_COUNT       = 32 // Number of relocations offset
	PE_SECTION_LINENUMBER_COUNT  = 34 // Number of line numbers offset
	PE_SECTION_CHARACTERISTICS   = 36 // Characteristics offset
)

const (
	// Data directory entries
	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0  // Export Table
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1  // Import Table
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2  // Resource Directory
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3  // Exception Directory
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4  // Security Directory
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5  // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6  // Debug Directory
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7  // Architecture Specific Data
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8  // RVA of GP
	IMAGE_DIRECTORY_ENTRY_TLS            = 9  // TLS Directory
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10 // Load Configuration Directory
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11 // Bound Import Directory
	IMAGE_DIRECTORY_ENTRY_IAT            = 12 // Import Address Table
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13 // Delay Load Import Descriptors
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 // COM Runtime descriptor
	IMAGE_DIRECTORY_ENTRY_RESERVED       = 15 // Reserved

	IMAGE_SIZEOF_DATA_DIRECTORY = 8
)

const (
	// Machine types
	IMAGE_FILE_MACHINE_I386  = 0x014c // Intel 386
	IMAGE_FILE_MACHINE_AMD64 = 0x8664 // AMD64 (K8)
	IMAGE_FILE_MACHINE_ARM   = 0x01c0 // ARM little endian
	IMAGE_FILE_MACHINE_ARM64 = 0xaa64 // ARM64 little endian
)

const (
	// Section characteristics
	IMAGE_SCN_CNT_CODE               = 0x00000020 // Contains executable code
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040 // Contains initialized data
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080 // Contains uninitialized data
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000 // Executable
	IMAGE_SCN_MEM_READ               = 0x40000000 // Readable
	IMAGE_SCN_MEM_WRITE              = 0x80000000 // Writable
)

const (
	// Alignment constants
	PE_FILE_ALIGNMENT_DEFAULT    = 0x200  // Default file alignment (512 bytes)
	PE_SECTION_ALIGNMENT_DEFAULT = 0x1000 // Default section alignment (4096 bytes)
	PE_FILE_ALIGNMENT_MIN        = 512    // Minimum file alignment
	PE_DATA_DIRECTORY_COUNT      = 16     // Number of data directory entries

	// Additional constants for parsing
	PE_SIGNATURE_SIZE           = 4  // Size of PE signature
	PE_MIN_OPTIONAL_HEADER_SIZE = 28 // Minimum optional header size

	// Rich Header analysis constants
	PE_MIN_DATA_FOR_RICH_ANALYSIS = 1024 // Minimum data size needed for Rich Header analysis
	PE_RICH_HEADER_SEARCH_LIMIT   = 4096 // Maximum bytes to search for Rich Header
)
