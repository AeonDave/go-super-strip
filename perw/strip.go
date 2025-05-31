package perw

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// --- Section Name Lists (Unexported) ---
var (
	// DebugSectionsExact lists names of sections commonly containing debugging information.
	debugSectionsExact = []string{
		".debug",   // Generic DWARF debug info (less common in PE but possible)
		".pdata",   // Procedure data for exception handling, also used by debuggers
		".xdata",   // Exception data, also used by debuggers
		".debug$S", // CodeView Symbols
		".debug$T", // CodeView Types
		".debug$P", // CodeView Precompiled Headers
		".debug$F", // CodeView FPO (Frame Pointer Omission) data
		// Other common CodeView section prefixes: .debug$ anything else
	}
	debugSectionsPrefix = []string{
		".debug$", // Covers all CodeView debug sections not explicitly listed
	}

	// SymbolSectionsExact lists names of sections containing symbol table information.
	// Note: PE files typically embed symbols within the debug directory or CodeView data,
	// rather than having a dedicated .symtab like ELF.
	symbolSectionsExact = []string{
		// PE files don't usually have a .symtab or .strtab in the same way ELF does.
		// Symbols are often in the debug directory (e.g., CodeView format) or stripped.
		// This list might be empty or contain very specific/rare section names if found.
	}

	// RelocSectionsExact lists names of sections containing base relocation information.
	// Stripping this from a non-ASLR DLL or an EXE that can't be loaded at its preferred base is problematic.
	relocSectionsExact = []string{
		".reloc",
	}

	// NonEssentialSectionsExact lists sections often considered non-essential for execution.
	// WARNING: Stripping .rsrc will remove icons, version info, dialogs etc.
	nonEssentialSectionsExact = []string{
		".comment", // Linker/compiler comments
		".note",    // Note sections, similar to ELF
		".drectve", // Linker directives
		".rsrc",    // Resource section (icons, version, dialogs, etc.)
		".shared",  // Sections for shared data among instances (rare)
		".cormeta", // CLR metadata section (.NET)
		".sxdata",  // Registered SEH handlers (part of exception handling)
	}

	// ExceptionSectionsExact lists names of sections critical for structured exception handling (SEH).
	// WARNING: Stripping these will likely break exception handling, especially in 64-bit code.
	exceptionSectionsExact = []string{
		".pdata", // Procedure data (function entry/exit points, unwind info)
		".xdata", // Unwind codes and exception handler addresses
		// .sxdata is also related but often grouped with non-essential for some strip tools
	}

	// BuildInfoSectionsExact lists sections that might contain build IDs or toolchain info.
	buildInfoSectionsExact = []string{
		".buildid", // Similar to ELF build ID
		".gfids",   // Control Flow Guard (CFG) function IDs
		".giats",   // CFG IAT table addresses
		".gljmp",   // CFG long jump targets
		".textbss", // MSVC specific, sometimes considered for stripping
	}
)

// --- Helper Functions ---

// ZeroFill fills a memory region with zeros.
func (p *PEFile) ZeroFill(offset int64, size int) error {
	if offset+int64(size) > int64(len(p.RawData)) {
		return fmt.Errorf("write beyond file limits: offset %d, size %d", offset, size)
	}
	for i := int64(0); i < int64(size); i++ {
		p.RawData[offset+i] = 0
	}
	return nil
}

// RandomFill fills a memory region with cryptographically secure random bytes.
func (p *PEFile) RandomFill(offset int64, size int) error {
	if offset < 0 || size < 0 || offset+int64(size) > int64(len(p.RawData)) {
		return fmt.Errorf("invalid offset/size for random fill: offset %d, size %d, total %d", offset, size, len(p.RawData))
	}
	if size == 0 {
		return nil
	}
	fillBytes := make([]byte, size)
	_, err := rand.Read(fillBytes)
	if err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}
	copy(p.RawData[offset:offset+int64(size)], fillBytes)
	return nil
}

// --- Core Stripping Logic ---

// StripSectionsByNames processes sections based on name match (exact or prefix).
// It can fill the section data with zeros or random bytes.
func (p *PEFile) StripSectionsByNames(names []string, prefix bool, useRandomFill bool) error {
	for i, section := range p.Sections {
		match := false
		for _, name := range names {
			if (prefix && strings.HasPrefix(section.Name, name)) || (!prefix && section.Name == name) {
				match = true
				break
			}
		}
		if match {
			if section.Offset > 0 && section.Size > 0 {
				var err error
				if useRandomFill {
					err = p.RandomFill(section.Offset, int(section.Size))
				} else {
					err = p.ZeroFill(section.Offset, int(section.Size))
				}
				if err != nil {
					return fmt.Errorf("failed to fill section %s: %w", section.Name, err)
				}
			}
			// Mark section as stripped by nullifying its size and offset in our internal list.
			// The actual removal from the file occurs if this space isn't covered by SizeOfImage
			// or if the section header entry itself is modified to have zero size.
			p.Sections[i].Offset = 0
			p.Sections[i].Size = 0
			// RVA also becomes meaningless if size is 0, though it's not directly zeroed here
			// as UpdateSectionHeaders will write size as 0.
		}
	}
	// After modifying sections, the section headers in RawData need to be updated.
	return p.UpdateSectionHeaders() // Assumes this method exists in perw/write.go
}

// StripByteRegex overwrites byte patterns matching a regex in sections.
// It can fill the matched data with zeros or random bytes.
func (p *PEFile) StripByteRegex(pattern *regexp.Regexp, useRandomFill bool) int {
	matchesTotal := 0
	for i := range p.Sections {
		section := &p.Sections[i]
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}

		readSize := section.Size
		if section.Offset+readSize > int64(len(p.RawData)) {
			readSize = int64(len(p.RawData)) - section.Offset
			if readSize <= 0 {
				continue
			}
		}

		sectionDataSlice := p.RawData[section.Offset : section.Offset+readSize]
		indices := pattern.FindAllIndex(sectionDataSlice, -1)
		if len(indices) == 0 {
			continue
		}

		for _, idx := range indices {
			start := idx[0]
			end := idx[1]
			for k := start; k < end; k++ {
				if useRandomFill {
					b := make([]byte, 1)
					_, err := rand.Read(b) // crypto/rand
					if err != nil {
						sectionDataSlice[k] = 0 // Fallback or handle error
						continue
					}
					sectionDataSlice[k] = b[0]
				} else {
					sectionDataSlice[k] = 0
				}
			}
			matchesTotal++
		}
	}
	return matchesTotal
}

// --- Specific Stripping Functions ---

// StripDebugSections removes common debugging information.
func (p *PEFile) StripDebugSections(useRandomFill bool) error {
	if err := p.StripSectionsByNames(debugSectionsExact, false, useRandomFill); err != nil {
		return fmt.Errorf("stripping exact debug sections: %w", err)
	}
	return p.StripSectionsByNames(debugSectionsPrefix, true, useRandomFill)
}

// StripSymbolTables is a placeholder as PE files usually don't have distinct .symtab sections like ELF.
// Symbols are typically in CodeView/.debug$ or stripped via the Debug Directory.
func (p *PEFile) StripSymbolTables(useRandomFill bool) error {
	// If specific symbol table section names are identified for PE, add them to symbolSectionsExact.
	// For now, this will likely do nothing unless symbolSectionsExact is populated.
	return p.StripSectionsByNames(symbolSectionsExact, false, useRandomFill)
}

// StripRelocationTable removes the .reloc section.
// WARNING: This can break executables if they are not DLLs or cannot be loaded at their preferred base address.
func (p *PEFile) StripRelocationTable(useRandomFill bool) error {
	return p.StripSectionsByNames(relocSectionsExact, false, useRandomFill)
}

// StripNonEssentialSections removes a curated list of sections generally not critical for execution.
// WARNING: This includes .rsrc, which contains icons, version info, etc.
func (p *PEFile) StripNonEssentialSections(useRandomFill bool) error {
	return p.StripSectionsByNames(nonEssentialSectionsExact, false, useRandomFill)
}

// StripExceptionHandlingData removes .pdata and .xdata sections.
// WARNING: This will likely break structured exception handling (SEH), especially in 64-bit applications.
func (p *PEFile) StripExceptionHandlingData(useRandomFill bool) error {
	return p.StripSectionsByNames(exceptionSectionsExact, false, useRandomFill)
}

// StripBuildInfoSections removes sections containing build IDs or specific toolchain/compiler info.
func (p *PEFile) StripBuildInfoSections(useRandomFill bool) error {
	return p.StripSectionsByNames(buildInfoSectionsExact, false, useRandomFill)
}

// StripAllMetadata attempts to remove a wide range of non-essential metadata.
// It can use zero-filling or random-filling.
// WARNING: This is aggressive and can break executables if not used carefully.
func (p *PEFile) StripAllMetadata(useRandomFill bool) error {
	if err := p.StripDebugSections(useRandomFill); err != nil {
		return fmt.Errorf("StripDebugSections failed: %w", err)
	}
	// p.StripSymbolTables(useRandomFill) // Usually no-op for PE, symbols are in debug data

	// Conditionally strip relocations: typically safer for DLLs.
	// For EXEs, stripping .reloc can be problematic if ASLR is active or base conflicts occur.
	if p.IsDLL() { // Assumes IsDLL() method exists
		if err := p.StripRelocationTable(useRandomFill); err != nil {
			return fmt.Errorf("StripRelocationTable for DLL failed: %w", err)
		}
	} else {
		// Consider making .reloc stripping for EXEs an explicit, separate option due to risk.
		// For now, let's not strip it by default from EXEs in StripAllMetadata.
		// fmt.Println("Skipping .reloc stripping for non-DLL file in StripAllMetadata.")
	}

	if err := p.StripNonEssentialSections(useRandomFill); err != nil {
		// Contains .rsrc, removing it has visual/functional impact.
		return fmt.Errorf("StripNonEssentialSections failed: %w", err)
	}

	// Highly risky, often breaks executables:
	// if err := p.StripExceptionHandlingData(useRandomFill); err != nil {
	// 	 return fmt.Errorf("StripExceptionHandlingData failed: %w", err)
	// }

	if err := p.StripBuildInfoSections(useRandomFill); err != nil {
		return fmt.Errorf("StripBuildInfoSections failed: %w", err)
	}

	// Randomizing section names is an obfuscation, not strictly stripping.
	if err := p.RandomizeSectionNames(); err != nil {
		return fmt.Errorf("RandomizeSectionNames failed: %w", err)
	}

	// ModifyPEHeader is also an obfuscation.
	// if err := p.ModifyPEHeader(); err != nil { // Ensure it uses crypto/rand
	// 	 return fmt.Errorf("ModifyPEHeader failed: %w", err)
	// }

	return nil
}

// --- Obfuscation Functions ---

// ModifyPEHeader modifies non-essential PE header fields using crypto/rand.
// Example: Randomizes the TimeDateStamp in the COFF File Header.
func (p *PEFile) ModifyPEHeader() error {
	if len(p.RawData) < 0x40 { // Basic check for DOS header size
		return fmt.Errorf("file too small for DOS header: %d bytes", len(p.RawData))
	}
	eLfanewOffset := int64(0x3C)
	if eLfanewOffset+4 > int64(len(p.RawData)) {
		return fmt.Errorf("cannot read e_lfanew, file too small")
	}
	eLfanew := int64(binary.LittleEndian.Uint32(p.RawData[eLfanewOffset : eLfanewOffset+4]))

	// COFF File Header starts at eLfanew + 4 (after PE signature)
	// TimeDateStamp is at offset 4 within the COFF File Header (so eLfanew + 4 + 4)
	tsOffset := eLfanew + 8
	if tsOffset+4 > int64(len(p.RawData)) { // Check if TimeDateStamp is within bounds
		return fmt.Errorf("TimeDateStamp offset out of bounds: %d", tsOffset)
	}

	randBytes := make([]byte, 4)
	_, err := rand.Read(randBytes) // crypto/rand
	if err != nil {
		return fmt.Errorf("failed to generate random bytes for TimeDateStamp: %w", err)
	}
	copy(p.RawData[tsOffset:tsOffset+4], randBytes)
	return nil
}

// RandomizeSectionNames renames sections with random-like names using crypto/rand.
// Section names in PE are max 8 bytes.
func (p *PEFile) RandomizeSectionNames() error {
	if len(p.RawData) < 0x40 {
		return fmt.Errorf("file too small for DOS header")
	}
	eLfanewOffset := int64(0x3C)
	if eLfanewOffset+4 > int64(len(p.RawData)) {
		return fmt.Errorf("cannot read e_lfanew, file too small")
	}
	eLfanew := int64(binary.LittleEndian.Uint32(p.RawData[eLfanewOffset : eLfanewOffset+4]))

	// PE Signature (4 bytes) + COFF FileHeader (20 bytes)
	peHeaderSize := eLfanew + 4 + 20
	if peHeaderSize+2 > int64(len(p.RawData)) { // Need at least up to SizeOfOptionalHeader
		return fmt.Errorf("file too small for COFF header or SizeOfOptionalHeader field")
	}

	sizeOfOptionalHeaderOffsetCorrect := eLfanew + 20
	if sizeOfOptionalHeaderOffsetCorrect+2 > int64(len(p.RawData)) {
		return fmt.Errorf("cannot read SizeOfOptionalHeader, file too small")
	}

	sizeOfOptionalHeader := int64(binary.LittleEndian.Uint16(p.RawData[sizeOfOptionalHeaderOffsetCorrect : sizeOfOptionalHeaderOffsetCorrect+2]))
	sectionTableOffset := eLfanew + 4 + 20 + sizeOfOptionalHeader // PE Sig + COFF Header + OptionalHeader

	randBytes := make([]byte, 8) // Max section name length

	for i := range p.Sections {
		currentSectionHeaderOffset := sectionTableOffset + int64(i*40) // Each section header is 40 bytes
		if currentSectionHeaderOffset+8 > int64(len(p.RawData)) {      // Check if section name field is within bounds
			return fmt.Errorf("section header %d name offset out of bounds", i)
		}

		_, err := rand.Read(randBytes) // crypto/rand
		if err != nil {
			return fmt.Errorf("failed to generate random bytes for section name %d: %w", i, err)
		}
		// Create a name like ".sXXXXXX" where X is a hex char, ensuring it starts with a dot if possible
		// and is null-padded/terminated within 8 bytes.
		randomName := make([]byte, 8)
		randomName[0] = '.'      // Standard PE sections often start with a dot
		for j := 1; j < 7; j++ { // Fill next 6 chars with random hex-like chars
			c := randBytes[j] % 16
			if c < 10 {
				randomName[j] = '0' + c
			} else {
				randomName[j] = 'a' + (c - 10)
			}
		}
		// The rest (randomName[7]) will be null by default from make([]byte, 8)

		copy(p.RawData[currentSectionHeaderOffset:currentSectionHeaderOffset+8], randomName)
		p.Sections[i].Name = strings.TrimRight(string(randomName), "\x00")
	}
	return nil
}

// IsDLL checks if the PE file is a DLL.
// This is a simplified check based on characteristics.
// func (p *PEFile) IsDLL() bool { // This function is now in perw/utils.go
//     if p.PE == nil {
//         return false // Cannot determine
//     }
//     // IMAGE_FILE_DLL characteristic
//     return (p.PE.FileHeader.Characteristics & 0x2000) != 0
// }
