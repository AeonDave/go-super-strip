package perw

import (
	"debug/pe"
	"encoding/binary"
	"os"
)

// DataDirectory represents a PE data directory entry (compatibility structure)
type DataDirectory struct {
	RVA  uint32
	Size uint32
}

// PEOffsets represents PE file offsets (compatibility structure)
type PEOffsets struct {
	OptionalHeader   int64
	NumberOfSections int
	FirstSectionHdr  int64
	ELfanew          int64
}

// ImageBase returns the image base address
func (p *PEFile) ImageBase() uint64 {
	if p.StdPE != nil {
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			return uint64(oh.ImageBase)
		case *pe.OptionalHeader64:
			return oh.ImageBase
		}
	}
	// Default fallback for 32-bit PE files
	if p.Is64Bit {
		return 0x140000000 // Common default for 64-bit PE files
	}
	return 0x400000 // Common default for 32-bit PE files
}

// EntryPoint returns the entry point
func (p *PEFile) EntryPoint() uint32 {
	if p.StdPE != nil {
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			return oh.AddressOfEntryPoint
		case *pe.OptionalHeader64:
			return oh.AddressOfEntryPoint
		}
	}
	// Try to extract from raw data if StdPE is not available
	if len(p.RawData) > 64 {
		ntHeaderOffset := binary.LittleEndian.Uint32(p.RawData[60:64])
		if ntHeaderOffset+24+28 < uint32(len(p.RawData)) {
			// AddressOfEntryPoint is at offset 16 in OptionalHeader (after Magic + LinkerVersion)
			entryPointOffset := ntHeaderOffset + 24 + 16
			return binary.LittleEndian.Uint32(p.RawData[entryPointOffset : entryPointOffset+4])
		}
	}
	return 0
}

// SizeOfImage returns the size of image
func (p *PEFile) SizeOfImage() uint32 {
	if p.StdPE != nil {
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			return oh.SizeOfImage
		case *pe.OptionalHeader64:
			return oh.SizeOfImage
		}
	}
	// Try to extract from raw data if StdPE is not available
	if len(p.RawData) > 64 {
		ntHeaderOffset := binary.LittleEndian.Uint32(p.RawData[60:64])
		if ntHeaderOffset+24+60 < uint32(len(p.RawData)) {
			// SizeOfImage is at offset 56 in OptionalHeader
			sizeOfImageOffset := ntHeaderOffset + 24 + 56
			return binary.LittleEndian.Uint32(p.RawData[sizeOfImageOffset : sizeOfImageOffset+4])
		}
	}
	return 0
}

// SizeOfHeaders returns the size of headers
func (p *PEFile) SizeOfHeaders() uint32 {
	if p.StdPE != nil {
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			return oh.SizeOfHeaders
		case *pe.OptionalHeader64:
			return oh.SizeOfHeaders
		}
	}
	// Try to extract from raw data if StdPE is not available
	if len(p.RawData) > 64 {
		ntHeaderOffset := binary.LittleEndian.Uint32(p.RawData[60:64])
		if ntHeaderOffset+24+60 < uint32(len(p.RawData)) {
			// SizeOfHeaders is at offset 60 in OptionalHeader
			sizeOfHeadersOffset := ntHeaderOffset + 24 + 60
			return binary.LittleEndian.Uint32(p.RawData[sizeOfHeadersOffset : sizeOfHeadersOffset+4])
		}
	}
	return 0
}

// Subsystem returns the subsystem
func (p *PEFile) Subsystem() uint16 {
	if p.StdPE != nil {
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			return oh.Subsystem
		case *pe.OptionalHeader64:
			return oh.Subsystem
		}
	}
	// Try to extract from raw data if StdPE is not available
	if len(p.RawData) > 64 {
		ntHeaderOffset := binary.LittleEndian.Uint32(p.RawData[60:64])
		if ntHeaderOffset+24+68 < uint32(len(p.RawData)) {
			// Subsystem is at offset 68 in OptionalHeader
			subsystemOffset := ntHeaderOffset + 24 + 68
			return binary.LittleEndian.Uint16(p.RawData[subsystemOffset : subsystemOffset+2])
		}
	}
	// Default to Windows Console
	return 3
}

// DllCharacteristics returns the DLL characteristics
func (p *PEFile) DllCharacteristics() uint16 {
	if p.StdPE != nil {
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			return oh.DllCharacteristics
		case *pe.OptionalHeader64:
			return oh.DllCharacteristics
		}
	}
	// Try to extract from raw data if StdPE is not available
	if len(p.RawData) > 64 {
		ntHeaderOffset := binary.LittleEndian.Uint32(p.RawData[60:64])
		if ntHeaderOffset+24+70 < uint32(len(p.RawData)) {
			// DllCharacteristics is at offset 70 in OptionalHeader
			dllCharsOffset := ntHeaderOffset + 24 + 70
			return binary.LittleEndian.Uint16(p.RawData[dllCharsOffset : dllCharsOffset+2])
		}
	}
	// Default characteristics (common characteristics)
	return 0x8140 // DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
}

// Checksum returns the checksum
func (p *PEFile) Checksum() uint32 {
	if p.StdPE != nil {
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			return oh.CheckSum
		case *pe.OptionalHeader64:
			return oh.CheckSum
		}
	}
	// Try to extract from raw data if StdPE is not available
	if len(p.RawData) > 64 {
		ntHeaderOffset := binary.LittleEndian.Uint32(p.RawData[60:64])
		if ntHeaderOffset+24+64 < uint32(len(p.RawData)) {
			// CheckSum is at offset 64 in OptionalHeader
			checksumOffset := ntHeaderOffset + 24 + 64
			return binary.LittleEndian.Uint32(p.RawData[checksumOffset : checksumOffset+4])
		}
	}
	return 0
}

// SignatureOffset returns the signature offset
func (p *PEFile) SignatureOffset() uint32 {
	if p.StdPE != nil {
		// Check if there's a certificate table in the data directories
		var certTableRVA, certTableSize uint32
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			certTableRVA = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
			certTableSize = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
		case *pe.OptionalHeader64:
			certTableRVA = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
			certTableSize = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
		}
		if certTableRVA > 0 && certTableSize > 0 {
			return certTableRVA // For security directory, RVA is actually a file offset
		}
	}
	return 0
}

// SignatureSize returns the signature size
func (p *PEFile) SignatureSize() uint32 {
	if p.StdPE != nil {
		// Check if there's a certificate table in the data directories
		var certTableSize uint32
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			certTableSize = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
		case *pe.OptionalHeader64:
			certTableSize = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
		}
		return certTableSize
	}
	return 0
}

// GetFileType returns the file type (EXE, DLL, etc.)
func (p *PEFile) GetFileType() string {
	if p.StdPE != nil {
		characteristics := p.StdPE.FileHeader.Characteristics
		if characteristics&pe.IMAGE_FILE_DLL != 0 {
			return "DLL"
		}
		if characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
			return "EXE"
		}
		return "Unknown"
	}
	// Try to extract from raw data if StdPE is not available
	if len(p.RawData) > 64 {
		ntHeaderOffset := binary.LittleEndian.Uint32(p.RawData[60:64])
		if ntHeaderOffset+24 < uint32(len(p.RawData)) {
			// Characteristics is at offset 18 in COFF header (after Signature + Machine + NumberOfSections + TimeDateStamp + PointerToSymbolTable + NumberOfSymbols + SizeOfOptionalHeader)
			characteristicsOffset := ntHeaderOffset + 4 + 18
			characteristics := binary.LittleEndian.Uint16(p.RawData[characteristicsOffset : characteristicsOffset+2])
			if characteristics&0x2000 != 0 { // IMAGE_FILE_DLL
				return "DLL"
			}
			if characteristics&0x0002 != 0 { // IMAGE_FILE_EXECUTABLE_IMAGE
				return "EXE"
			}
		}
	}
	return "EXE" // Default fallback
}

func (p *PEFile) Directories() []DataDirectory {
	var directories []DataDirectory
	if p.StdPE != nil {
		switch oh := p.StdPE.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			for _, dir := range oh.DataDirectory {
				directories = append(directories, DataDirectory{
					RVA:  dir.VirtualAddress,
					Size: dir.Size,
				})
			}
		case *pe.OptionalHeader64:
			for _, dir := range oh.DataDirectory {
				directories = append(directories, DataDirectory{
					RVA:  dir.VirtualAddress,
					Size: dir.Size,
				})
			}
		}
	}
	return directories
}

// calculateOffsets returns PE header offsets
func (p *PEFile) calculateOffsets() (*PEOffsets, error) {
	if len(p.RawData) < 64 {
		return nil, os.ErrInvalid
	}

	// Get NT header offset from DOS header
	elfanew := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))

	// Calculate offsets
	optionalHeaderOffset := elfanew + 24 // After NT signature (4) + COFF header (20)

	var sizeOfOptionalHeader uint16
	if elfanew+22 < int64(len(p.RawData)) {
		sizeOfOptionalHeader = binary.LittleEndian.Uint16(p.RawData[elfanew+20 : elfanew+22])
	}

	firstSectionHdr := optionalHeaderOffset + int64(sizeOfOptionalHeader)

	var numberOfSections int
	if elfanew+6 < int64(len(p.RawData)) {
		numberOfSections = int(binary.LittleEndian.Uint16(p.RawData[elfanew+6 : elfanew+8]))
	}

	return &PEOffsets{
		OptionalHeader:   optionalHeaderOffset,
		NumberOfSections: numberOfSections,
		FirstSectionHdr:  firstSectionHdr,
		ELfanew:          elfanew,
	}, nil
}

// validateOffset validates that an offset is valid within the file
func (p *PEFile) validateOffset(offset int64, size int) error {
	if offset < 0 || offset+int64(size) > int64(len(p.RawData)) {
		return os.ErrInvalid
	}
	return nil
}

// findSectionByName finds a section by name
func (p *PEFile) findSectionByName(name string) *Section {
	for i := range p.Sections {
		if p.Sections[i].Name == name {
			return &p.Sections[i]
		}
	}
	return nil
}

// PE returns the underlying PE structure
func (p *PEFile) PE() interface{} {
	if p.StdPE != nil {
		return p.StdPE
	}
	return p.VeloxPE
}

// IsPEFile checks if a file is a valid PE file
func IsPEFile(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Read DOS header
	dosHeader := make([]byte, 64)
	_, err = file.Read(dosHeader)
	if err != nil {
		return false, err
	}

	// Check MZ signature
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return false, nil
	}

	// Get NT header offset
	ntHeaderOffset := binary.LittleEndian.Uint32(dosHeader[60:64])

	// Read NT signature
	_, _ = file.Seek(int64(ntHeaderOffset), 0)
	ntSig := make([]byte, 4)
	_, err = file.Read(ntSig)
	if err != nil {
		return false, err
	}

	// Check PE signature
	return ntSig[0] == 'P' && ntSig[1] == 'E' && ntSig[2] == 0 && ntSig[3] == 0, nil
}
