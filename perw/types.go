package perw

import (
	"debug/pe"
	"os"
)

type Section struct {
	Name           string
	Offset         int64
	Size           int64
	VirtualAddress uint32
	VirtualSize    uint32
	Index          int
	Flags          uint32
	RVA            uint32
	Entropy        float64
	MD5Hash        string
	SHA1Hash       string
	SHA256Hash     string
	FileOffset     uint32
	IsExecutable   bool
	IsReadable     bool
	IsWritable     bool
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
	usedFallbackMode   bool // Tracks if we used fallback mode for section insertion
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

type ParseMode int

type ParseResult struct {
	Mode     ParseMode
	Success  bool
	Reason   string
	Warnings []string
}
