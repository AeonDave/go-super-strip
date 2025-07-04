package perw

import (
	"debug/pe"
	"os"
)

type PEFile struct {
	File     *os.File
	PE       *pe.File
	Is64Bit  bool
	FileName string
	Sections []Section
	RawData  []byte

	imageBase          uint64
	entryPoint         uint32
	sizeOfImage        uint32
	sizeOfHeaders      uint32
	checksum           uint32
	subsystem          uint16
	dllCharacteristics uint16
	Machine            string
	TimeDateStamp      string

	directories []DirectoryEntry

	Imports []ImportInfo
	Exports []ExportInfo

	FileSize      int64
	IsPacked      bool
	HasOverlay    bool
	OverlayOffset int64
	OverlaySize   int64

	SignatureOffset int64
	signatureSize   int64

	PDBPath string
	guidAge string

	versionInfo map[string]string
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
	Entropy              float64
	MD5Hash              string
	SHA1Hash             string
	SHA256Hash           string
	FileOffset           uint32
	IsExecutable         bool
	IsReadable           bool
	IsWritable           bool
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
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

type ParseMode int

type ParseResult struct {
	Mode     ParseMode
	Success  bool
	Reason   string
	Warnings []string
}

const (
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
)
