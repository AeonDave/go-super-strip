package elfrw

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// --- Helper Functions ---

// IsLittleEndian checks if the ELF file uses little-endian byte order.
func (e *ELFFile) IsLittleEndian() bool {
	return e.RawData[5] == 1 // EI_DATA field, 1 for LSB
}

// GetEndian returns the binary.ByteOrder for the ELF file.
func (e *ELFFile) GetEndian() binary.ByteOrder {
	if e.IsLittleEndian() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// ReadBytes reads a slice of bytes from RawData at a given offset.
func (e *ELFFile) ReadBytes(offset uint64, size int) ([]byte, error) {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return nil, fmt.Errorf("read beyond file limits: offset %d, size %d, file size %d", offset, size, len(e.RawData))
	}
	result := make([]byte, size)
	copy(result, e.RawData[offset:offset+uint64(size)])
	return result, nil
}

// ZeroFill overwrites a region of RawData with zeros.
func (e *ELFFile) ZeroFill(offset uint64, size int) error {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return fmt.Errorf("write beyond file limits: offset %d, size %d, file size %d", offset, size, len(e.RawData))
	}
	for i := uint64(0); i < uint64(size); i++ {
		e.RawData[offset+i] = 0
	}
	return nil
}

// RandomFill overwrites a region of RawData with random bytes.
func (e *ELFFile) RandomFill(offset uint64, size int) error {
	if offset+uint64(size) > uint64(len(e.RawData)) {
		return fmt.Errorf("write beyond file limits: offset %d, size %d, file size %d", offset, size, len(e.RawData))
	}
	// Ensure that if size is 0, we don't try to slice with a negative upper bound if offset is also 0.
	if size == 0 {
		return nil
	}
	fillBytes := make([]byte, size)
	_, err := rand.Read(fillBytes)
	if err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}
	copy(e.RawData[offset:offset+uint64(size)], fillBytes)
	return nil
}

// --- Section Name Lists (Unexported) ---

var (
	// SymbolsSectionsExact lists names of sections containing symbol table information.
	symbolsSectionsExact = []string{
		".symtab", // Standard symbol table
		// Note: .dynsym is often essential for dynamic linking, handled separately if stripping dynamic info
	}

	// StringSectionsExact lists names of general string table sections.
	stringSectionsExact = []string{
		".strtab", // Standard string table
		// Note: .dynstr is often essential for dynamic linking, handled separately
	}

	// DebugSectionsExact lists names of sections commonly containing debugging information.
	debugSectionsExact = []string{
		".debug",           // Generic debug section (often a prefix)
		".stab",            // Symbol table strings for STABS debug format
		".stabstr",         // STABS string table
		".gdb_index",       // GDB index section
		".line",            // Line number information
		".zdebug_abbrev",   // Compressed DWARF abbreviation table
		".zdebug_aranges",  // Compressed DWARF address ranges
		".zdebug_frame",    // Compressed DWARF call frame information
		".zdebug_info",     // Compressed DWARF core debug information
		".zdebug_line",     // Compressed DWARF line number information
		".zdebug_loc",      // Compressed DWARF location lists
		".zdebug_macinfo",  // Compressed DWARF macro information
		".zdebug_pubnames", // Compressed DWARF public names
		".zdebug_pubtypes", // Compressed DWARF public types
		".zdebug_ranges",   // Compressed DWARF address ranges
		".zdebug_str",      // Compressed DWARF strings
		".zdebug_loclists", // Compressed DWARF location lists (DWARF5)
		".zdebug_rnglists", // Compressed DWARF range lists (DWARF5)
		".debug_abbrev",
		".debug_addr",
		".debug_aranges",
		".debug_attr",
		".debug_cu_index",
		".debug_frame",
		".debug_gnu_pubnames",
		".debug_gnu_pubtypes",
		".debug_info",
		".debug_line",
		".debug_line_str",
		".debug_loc",
		".debug_loclists",
		".debug_macinfo",
		".debug_macro",
		".debug_pubnames",
		".debug_pubtypes",
		".debug_ranges",
		".debug_rnglists",
		".debug_str",
		".debug_str_offsets",
		".debug_tu_index",
		".debug_types",
	}
	// DebugSectionsPrefix lists common prefixes for debug sections.
	debugSectionsPrefix = []string{
		".debug_",     // DWARF sections often start with this
		".zdebug_",    // Compressed DWARF sections
		".gnu.debugl", // GNU specific debug link sections
	}

	// BuildInfoSectionsExact lists names of sections containing build IDs, notes, comments, etc.
	buildInfoSectionsExact = []string{
		".gnu.build.attributes",
		".gnu.version",
		".gnu.version_r", // Version requirement
		".gnu.version_d", // Version definition
		".gnu.warning",
		".note.gnu.build-id",
		".note.ABI-tag",
		".note.gnu.property", // GNU property notes
		".comment",
		".buildid",
		".SUNW_cap",
		".SUNW_signature",
	}
	// BuildInfoSectionsPrefix lists common prefixes for note and other build info sections.
	buildInfoSectionsPrefix = []string{
		".note",  // General note sections
		".SUNW_", // Solaris specific
		".ident", // Often contains compiler/linker identification
	}

	// ProfilingSectionsExact lists names of sections related to profiling.
	profilingSectionsExact = []string{
		".gmon",    // gprof profiling data
		".profile", // General profiling data
	}

	// ExceptionSectionsExact lists names of sections for exception handling and stack unwinding.
	// WARNING: Stripping these can break C++ exception handling and stack unwinding for debuggers.
	exceptionSectionsExact = []string{
		".eh_frame",
		".eh_frame_hdr",
		".gcc_except_table",
		".ARM.exidx", // ARM exception index table
		".ARM.extab", // ARM exception table
	}
	// ExceptionSectionsPrefix lists common prefixes for exception related sections.
	exceptionSectionsPrefix = []string{
		".pdr",    // (OS/2, Win32) Procedure Descriptor Records, sometimes seen in ELF for compatibility layers
		".mdebug", // MIPS specific debug/exception info
	}

	// ArchSectionsPrefix lists common prefixes for architecture-specific sections.
	archSectionsPrefix = []string{
		".ARM.",    // ARM specific
		".MIPS.",   // MIPS specific
		".xtensa.", // Xtensa specific
	}

	// DynamicLinkingSections lists sections critical for dynamic linking.
	// WARNING: Stripping these will likely break dynamically linked executables.
	dynamicLinkingSections = []string{
		".dynamic",
		".dynsym",
		".dynstr",
		".interp",
		".hash",
		".gnu.hash",
		".got",
		".got.plt",
		".plt",
		".plt.got",
		".plt.sec",
	}
	// RelocationSectionsPrefix lists common prefixes for relocation sections.
	// WARNING: Stripping these will likely break dynamically linked executables.
	relocationSectionsPrefix = []string{
		".rel.",  // Relocations without addends
		".rela.", // Relocations with addends
	}
)

// --- Core Stripping Logic ---

// StripSectionsByNames processes sections based on name match (exact or prefix).
// It can fill the section data with zeros or random bytes.
func (e *ELFFile) StripSectionsByNames(names []string, prefix bool, useRandomFill bool) error {
	for i, section := range e.Sections {
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
					err = e.RandomFill(section.Offset, int(section.Size))
				} else {
					err = e.ZeroFill(section.Offset, int(section.Size))
				}
				if err != nil {
					return fmt.Errorf("failed to fill section %s: %w", section.Name, err)
				}
			}
			// Mark section as stripped by nullifying its size and offset in our internal list.
			// The actual removal from the file occurs if this space isn't part of a loadable segment
			// and the section header table itself is removed or zeroed.
			e.Sections[i].Offset = 0
			e.Sections[i].Size = 0
		}
	}
	// After modifying sections, the section headers in RawData need to be updated.
	return e.UpdateSectionHeaders()
}

// StripByteRegex overwrites byte patterns matching a regex in all sections.
// It can fill the matched data with zeros or random bytes.
func (e *ELFFile) StripByteRegex(pattern *regexp.Regexp, useRandomFill bool) int {
	matchesTotal := 0
	for i := range e.Sections {
		section := &e.Sections[i] // Use pointer to modify original if needed, though not done here
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}
		// Read section data directly from RawData.
		// Ensure we don't read past the end of RawData, even if section.Size is corrupted.
		readSize := section.Size
		if section.Offset+readSize > uint64(len(e.RawData)) {
			readSize = uint64(len(e.RawData)) - section.Offset
			if readSize == 0 && section.Offset == uint64(len(e.RawData)) { // section offset is at the very end or past it
				continue
			}
			if readSize < 0 { // section offset is past the end
				continue
			}
		}
		if readSize == 0 {
			continue
		}

		sectionDataSlice := e.RawData[section.Offset : section.Offset+readSize]

		indices := pattern.FindAllIndex(sectionDataSlice, -1)
		if len(indices) == 0 {
			continue
		}

		for _, idx := range indices {
			start := idx[0]
			end := idx[1]
			for k := start; k < end; k++ {
				if useRandomFill {
					// Directly modify the slice from e.RawData
					b := make([]byte, 1)
					_, err := rand.Read(b)
					if err != nil {
						// On error, fallback to zero or handle as critical error
						sectionDataSlice[k] = 0
						continue // Or return an error/log
					}
					sectionDataSlice[k] = b[0]
				} else {
					sectionDataSlice[k] = 0
				}
			}
			matchesTotal++
		}
		// Data is modified in place in e.RawData, no need to copy back if sectionDataSlice was a direct slice.
	}
	return matchesTotal
}

// --- Specific Stripping Functions ---

// StripSectionTable removes references to the section header table from the ELF header.
// This makes sections "invisible" to most tools. The section data might still exist
// if it's part of a loadable segment, or it might be truncated if not.
func (e *ELFFile) StripSectionTable() error {
	shoffPos, shNumPos, shStrNdxPos := e.getHeaderPositions() // From write.go (assuming it's part of ELFFile struct or accessible)

	// Zero out e_shoff (section header table offset)
	if e.Is64Bit {
		if err := e.writeAtOffset(shoffPos, uint64(0)); err != nil { // writeAtOffset is from write.go
			return fmt.Errorf("failed to zero e_shoff (64-bit): %w", err)
		}
	} else {
		if err := e.writeAtOffset(shoffPos, uint32(0)); err != nil {
			return fmt.Errorf("failed to zero e_shoff (32-bit): %w", err)
		}
	}
	// Zero out e_shnum (number of section headers)
	if err := e.writeAtOffset(shNumPos, uint16(0)); err != nil {
		return fmt.Errorf("failed to zero e_shnum: %w", err)
	}
	// Zero out e_shstrndx (section header string table index)
	if err := e.writeAtOffset(shStrNdxPos, uint16(0)); err != nil {
		return fmt.Errorf("failed to zero e_shstrndx: %w", err)
	}
	// Effectively, sections are now gone from the header's perspective
	// No need to call e.UpdateSectionHeaders() as the table itself is marked non-existent.
	// Individual section structs in e.Sections are not changed here, but they won't be written
	// if the section header table is gone (unless they are part of PT_LOAD segments).
	return nil
}

// StripNonLoadableSegments zeros out data and metadata for non-PT_LOAD segments.
// This is aggressive and might remove essential non-loadable data like dynamic linking info
// if it's not in a PT_LOAD segment (though usually it is).
func (e *ELFFile) StripNonLoadableSegments(useRandomFill bool) error {
	for i, segment := range e.Segments {
		if !segment.Loadable { // PT_LOAD has type 1
			if segment.Offset > 0 && segment.Size > 0 {
				var err error
				if useRandomFill {
					err = e.RandomFill(segment.Offset, int(segment.Size))
				} else {
					err = e.ZeroFill(segment.Offset, int(segment.Size))
				}
				if err != nil {
					return fmt.Errorf("failed to fill non-loadable segment %d: %w", i, err)
				}
			}
			// Update internal segment representation
			e.Segments[i].Offset = 0
			e.Segments[i].Size = 0
			// Also update type or flags if necessary, though zeroing offset/size is primary
		}
	}
	return e.UpdateProgramHeaders() // Update program headers in RawData
}

// StripDebugSections removes common debugging information.
func (e *ELFFile) StripDebugSections(useRandomFill bool) error {
	if err := e.StripSectionsByNames(debugSectionsExact, false, useRandomFill); err != nil {
		return fmt.Errorf("stripping exact debug sections: %w", err)
	}
	if err := e.StripSectionsByNames(debugSectionsPrefix, true, useRandomFill); err != nil {
		return fmt.Errorf("stripping prefix debug sections: %w", err)
	}
	return nil
}

// StripSymbolTables removes symbol table sections (like .symtab).
// Note: .dynsym (dynamic symbols) is critical for dynamic linking and handled by StripDynamicLinkingData.
func (e *ELFFile) StripSymbolTables(useRandomFill bool) error {
	return e.StripSectionsByNames(symbolsSectionsExact, false, useRandomFill)
}

// StripStringTables removes general string table sections (like .strtab).
// Note: .dynstr (dynamic strings) is critical for dynamic linking and handled by StripDynamicLinkingData.
func (e *ELFFile) StripStringTables(useRandomFill bool) error {
	return e.StripSectionsByNames(stringSectionsExact, false, useRandomFill)
}

// StripBuildInfoSections removes sections containing build IDs, notes, comments, etc.
func (e *ELFFile) StripBuildInfoSections(useRandomFill bool) error {
	if err := e.StripSectionsByNames(buildInfoSectionsExact, false, useRandomFill); err != nil {
		return fmt.Errorf("stripping exact build info sections: %w", err)
	}
	if err := e.StripSectionsByNames(buildInfoSectionsPrefix, true, useRandomFill); err != nil {
		return fmt.Errorf("stripping prefix build info sections: %w", err)
	}
	return nil
}

// StripProfilingSections removes profiling related sections.
func (e *ELFFile) StripProfilingSections(useRandomFill bool) error {
	return e.StripSectionsByNames(profilingSectionsExact, false, useRandomFill)
}

// StripExceptionSections removes exception handling and stack unwinding sections.
// WARNING: This can break C++ exception handling and debugger stack unwinding.
func (e *ELFFile) StripExceptionSections(useRandomFill bool) error {
	if err := e.StripSectionsByNames(exceptionSectionsExact, false, useRandomFill); err != nil {
		return fmt.Errorf("stripping exact exception sections: %w", err)
	}
	if err := e.StripSectionsByNames(exceptionSectionsPrefix, true, useRandomFill); err != nil {
		return fmt.Errorf("stripping prefix exception sections: %w", err)
	}
	return nil
}

// StripArchSections removes common architecture-specific metadata sections.
func (e *ELFFile) StripArchSections(useRandomFill bool) error {
	return e.StripSectionsByNames(archSectionsPrefix, true, useRandomFill)
}

// StripRelocationSections removes relocation sections (.rel, .rela).
// WARNING: This will break dynamically linked executables if they rely on these relocations.
// It is often paired with stripping dynamic linking symbols and GOT/PLT.
func (e *ELFFile) StripRelocationSections(useRandomFill bool) error {
	return e.StripSectionsByNames(relocationSectionsPrefix, true, useRandomFill)
}

// StripDynamicLinkingData removes sections critical for dynamic linking.
// WARNING: This will almost certainly break dynamically linked executables.
// Use with extreme caution, typically only if aiming for a fully static-like (but broken) executable
// or for analysis where dynamic behavior is not required.
func (e *ELFFile) StripDynamicLinkingData(useRandomFill bool) error {
	// This includes .dynamic, .dynsym, .dynstr, .interp, .hash, .gnu.hash, .got, .plt etc.
	// and their associated relocations which are covered by StripRelocationSections.
	if err := e.StripSectionsByNames(dynamicLinkingSections, false, useRandomFill); err != nil {
		return fmt.Errorf("stripping dynamic linking sections: %w", err)
	}
	// Also strip relocations, as they are tightly coupled
	if err := e.StripRelocationSections(useRandomFill); err != nil {
		return fmt.Errorf("stripping relocations during dynamic linking strip: %w", err)
	}
	return nil
}

// ModifyELFHeader randomizes or clears non-critical ELF header fields.
// This is more of an obfuscation technique.
func (e *ELFFile) ModifyELFHeader() error {
	// Example: Randomize e_ident[EI_OSABI] and e_ident[EI_ABIVERSION]
	// These are often 0 (System V) anyway.
	b := make([]byte, 2)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Errorf("failed to generate random bytes for EI_OSABI/EI_ABIVERSION: %w", err)
	}
	e.RawData[7] = b[0] // EI_OSABI
	e.RawData[8] = b[1] // EI_ABIVERSION

	// Example: Randomize e_flags (processor-specific flags)
	var flagsOffset int
	if e.Is64Bit { // e_flags is at offset 0x30 for 64-bit
		flagsOffset = 0x30
	} else { // e_flags is at offset 0x24 for 32-bit
		flagsOffset = 0x24
	}
	// Write random 4 bytes. Be careful as some flags might be meaningful.
	// For true obfuscation, one might set them to valid but uncommon values.
	randBytes := make([]byte, 4)
	_, err = rand.Read(randBytes)
	if err != nil {
		return fmt.Errorf("failed to generate random bytes for e_flags: %w", err)
	}
	// Use existing writeAtOffset, assuming it can handle a []byte or we adapt it.
	// For simplicity, let's assume writeAtOffset uses binary.Write which might not directly take []byte.
	// A direct copy is safer here, or ensure writeAtOffset handles []byte or use GetEndian().PutUint32.
	if len(e.RawData) < flagsOffset+4 {
		return fmt.Errorf("e_flags offset out of bounds")
	}
	copy(e.RawData[flagsOffset:flagsOffset+4], randBytes)

	return nil
}

// StripAllMetadata attempts to remove a wide range of non-essential metadata.
// It can use zero-filling or random-filling.
// WARNING: This is very aggressive and can easily break executables, especially
// if they are dynamically linked or rely on C++ exceptions.
func (e *ELFFile) StripAllMetadata(useRandomFill bool) error {
	// Crucial step: Remove the section header table reference first.
	// This makes subsequent section stripping mainly about zeroing/randomizing content
	// that might be part of loadable segments.
	// If not part of loadable segments, it will be truncated by CommitChanges if size is reduced.
	if err := e.StripSectionTable(); err != nil {
		return fmt.Errorf("StripSectionTable failed: %w", err)
	}

	// Strip various categories of sections.
	// The order might matter if sections overlap or if some stripping actions
	// simplify others. Generally, StripSectionTable first is a good approach.

	if err := e.StripDebugSections(useRandomFill); err != nil {
		return fmt.Errorf("StripDebugSections failed: %w", err)
	}
	if err := e.StripSymbolTables(useRandomFill); err != nil {
		// .dynsym is handled by StripDynamicLinkingData
		return fmt.Errorf("StripSymbolTables failed: %w", err)
	}
	if err := e.StripStringTables(useRandomFill); err != nil {
		// .dynstr is handled by StripDynamicLinkingData
		return fmt.Errorf("StripStringTables failed: %w", err)
	}
	if err := e.StripBuildInfoSections(useRandomFill); err != nil {
		return fmt.Errorf("StripBuildInfoSections failed: %w", err)
	}
	if err := e.StripProfilingSections(useRandomFill); err != nil {
		return fmt.Errorf("StripProfilingSections failed: %w", err)
	}

	// More aggressive, higher risk of breaking functionality:
	if err := e.StripExceptionSections(useRandomFill); err != nil {
		// Breaks C++ exceptions, stack unwinding
		return fmt.Errorf("StripExceptionSections failed: %w", err)
	}
	if err := e.StripArchSections(useRandomFill); err != nil {
		return fmt.Errorf("StripArchSections failed: %w", err)
	}

	// Extremely aggressive, will break dynamic linking:
	// Only use if this is the explicit goal.
	// if err := e.StripDynamicLinkingData(useRandomFill); err != nil {
	// 	 return fmt.Errorf("StripDynamicLinkingData failed: %w", err)
	// }

	// Obfuscate ELF header fields (optional, not strictly stripping)
	// if err := e.ModifyELFHeader(); err != nil {
	// 	return fmt.Errorf("ModifyELFHeader failed: %w", err)
	// }

	// Consider stripping non-loadable program segments if they contain data not otherwise covered.
	// This is risky as non-loadable segments can still contain important metadata
	// (e.g., PHDR itself, INTERP if not loaded, notes).
	// if err := e.StripNonLoadableSegments(useRandomFill); err != nil {
	// 	return fmt.Errorf("StripNonLoadableSegments failed: %w", err)
	// }

	// After all section content modifications, ensure program headers are updated if segments were changed.
	// (StripSectionsByNames already calls UpdateSectionHeaders).
	// If StripNonLoadableSegments was called, it updates program headers.
	// If only section content within existing segments was changed, and segment layout itself is unchanged,
	// program headers might not need an update beyond what UpdateSectionHeaders does.
	// However, if sections that defined the extent of a segment are removed, the segment size in
	// program headers might need adjustment, which is not explicitly handled here yet.

	return nil
}

// Note: The functions getHeaderPositions(), writeAtOffset() are assumed to be methods of ELFFile
// and defined in elfrw/write.go or another part of the package.
// If they are not, they would need to be passed e.RawData, endianness etc. or e itself.
