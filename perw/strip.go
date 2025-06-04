package perw

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
)

// SectionType represents the type of sections for stripping
type SectionType int

const (
	DebugSections SectionType = iota
	SymbolSections
	RelocationSections
	NonEssentialSections
	ExceptionSections
	BuildInfoSections
)

// SectionMatcher holds section matching rules
type SectionMatcher struct {
	ExactNames  []string
	PrefixNames []string
	Description string
	StripForDLL bool // Whether to strip for DLL files
	StripForEXE bool // Whether to strip for EXE files
	IsRisky     bool // Whether stripping might break functionality
}

// sectionMatchers defines all section types and their matching rules
var sectionMatchers = map[SectionType]SectionMatcher{
	DebugSections: {
		ExactNames: []string{
			".debug", ".pdata", ".xdata", ".debug$S",
			".debug$T", ".debug$P", ".debug$F",
		},
		PrefixNames: []string{".debug$"},
		Description: "debugging information",
		StripForDLL: true,
		StripForEXE: true,
		IsRisky:     false,
	},
	SymbolSections: {
		ExactNames:  []string{}, // PE files typically don't have .symtab
		PrefixNames: []string{},
		Description: "symbol table information",
		StripForDLL: true,
		StripForEXE: true,
		IsRisky:     false,
	},
	RelocationSections: {
		ExactNames:  []string{".reloc"},
		PrefixNames: []string{},
		Description: "base relocation information",
		StripForDLL: true,
		StripForEXE: false, // Risky for EXE files
		IsRisky:     true,
	},
	NonEssentialSections: {
		ExactNames: []string{
			".comment", ".note", ".drectve", ".rsrc",
			".shared", ".cormeta", ".sxdata",
		},
		PrefixNames: []string{},
		Description: "non-essential metadata",
		StripForDLL: true,
		StripForEXE: true,
		IsRisky:     false,
	},
	ExceptionSections: {
		ExactNames:  []string{".pdata", ".xdata"},
		PrefixNames: []string{},
		Description: "structured exception handling data",
		StripForDLL: false,
		StripForEXE: false,
		IsRisky:     true,
	},
	BuildInfoSections: {
		ExactNames: []string{
			".buildid", ".gfids", ".giats", ".gljmp", ".textbss",
		},
		PrefixNames: []string{},
		Description: "build information and toolchain metadata",
		StripForDLL: true,
		StripForEXE: true,
		IsRisky:     false,
	},
}

// FillMode represents the type of data filling
type FillMode int

const (
	ZeroFill FillMode = iota
	RandomFill
)

// --- Core Helper Functions ---

// fillRegion fills a memory region with zeros or random bytes
func (p *PEFile) fillRegion(offset int64, size int, mode FillMode) error {
	if offset < 0 || size < 0 || offset+int64(size) > int64(len(p.RawData)) {
		return fmt.Errorf("invalid region: offset %d, size %d, total %d", offset, size, len(p.RawData))
	}

	if size == 0 {
		return nil
	}

	switch mode {
	case ZeroFill:
		for i := int64(0); i < int64(size); i++ {
			p.RawData[offset+i] = 0
		}
	case RandomFill:
		fillBytes := make([]byte, size)
		if _, err := rand.Read(fillBytes); err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
		copy(p.RawData[offset:offset+int64(size)], fillBytes)
	default:
		return fmt.Errorf("unknown fill mode: %v", mode)
	}

	return nil
}

// sectionMatches checks if a section name matches the given matcher
func sectionMatches(sectionName string, matcher SectionMatcher) bool {
	// Check exact matches
	for _, name := range matcher.ExactNames {
		if sectionName == name {
			return true
		}
	}

	// Check prefix matches
	for _, prefix := range matcher.PrefixNames {
		if strings.HasPrefix(sectionName, prefix) {
			return true
		}
	}

	return false
}

// --- Core Stripping Logic ---

// StripSectionsByType strips sections based on their type
func (p *PEFile) StripSectionsByType(sectionType SectionType, fillMode FillMode) error {
	matcher, exists := sectionMatchers[sectionType]
	if !exists {
		return fmt.Errorf("unknown section type: %v", sectionType)
	}

	// Check if we should strip this type for the current file
	if !p.shouldStripForFileType(sectionType) {
		return nil // Skip stripping for this file type
	}

	strippedCount := 0
	for _, section := range p.Sections {
		if !sectionMatches(section.Name, matcher) {
			continue
		}

		if section.Offset > 0 && section.Size > 0 {
			if err := p.fillRegion(section.Offset, int(section.Size), fillMode); err != nil {
				return fmt.Errorf("failed to fill section %s: %w", section.Name, err)
			}
		}

		// Just mark the section as processed, don't zero out the headers
		// PE files need valid section headers even if the content is stripped
		strippedCount++
	}

	// No need to update section headers since we're not changing the structure
	return nil
}

// StripSectionsByNames provides the original interface for backward compatibility
func (p *PEFile) StripSectionsByNames(names []string, prefix bool, useRandomFill bool) error {
	fillMode := ZeroFill
	if useRandomFill {
		fillMode = RandomFill
	}

	for _, section := range p.Sections {
		match := false
		for _, name := range names {
			if (prefix && strings.HasPrefix(section.Name, name)) || (!prefix && section.Name == name) {
				match = true
				break
			}
		}

		if !match {
			continue
		}

		if section.Offset > 0 && section.Size > 0 {
			if err := p.fillRegion(section.Offset, int(section.Size), fillMode); err != nil {
				return fmt.Errorf("failed to fill section %s: %w", section.Name, err)
			}
		}

		// Don't modify section headers, just clear content
	}

	return nil
}

// StripBytePattern overwrites byte patterns matching a regex in sections
func (p *PEFile) StripBytePattern(pattern *regexp.Regexp, fillMode FillMode) (int, error) {
	if pattern == nil {
		return 0, fmt.Errorf("regex pattern cannot be nil")
	}

	totalMatches := 0
	for _, section := range p.Sections {
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

		sectionData := p.RawData[section.Offset : section.Offset+readSize]
		matches := pattern.FindAllIndex(sectionData, -1)

		for _, match := range matches {
			start, end := match[0], match[1]
			if err := p.fillRegion(section.Offset+int64(start), end-start, fillMode); err != nil {
				return totalMatches, fmt.Errorf("failed to fill pattern match: %w", err)
			}
			totalMatches++
		}
	}

	return totalMatches, nil
}

// --- Convenience Functions ---

// StripDebugSections removes debugging information
func (p *PEFile) StripDebugSections(useRandomFill bool) error {
	fillMode := ZeroFill
	if useRandomFill {
		fillMode = RandomFill
	}
	return p.StripSectionsByType(DebugSections, fillMode)
}

// StripSymbolTables removes symbol table information (usually no-op for PE)
func (p *PEFile) StripSymbolTables(useRandomFill bool) error {
	fillMode := ZeroFill
	if useRandomFill {
		fillMode = RandomFill
	}
	return p.StripSectionsByType(SymbolSections, fillMode)
}

// StripRelocationTable removes base relocation information
func (p *PEFile) StripRelocationTable(useRandomFill bool) error {
	fillMode := ZeroFill
	if useRandomFill {
		fillMode = RandomFill
	}
	return p.StripSectionsByType(RelocationSections, fillMode)
}

// StripNonEssentialSections removes non-essential metadata
func (p *PEFile) StripNonEssentialSections(useRandomFill bool) error {
	fillMode := ZeroFill
	if useRandomFill {
		fillMode = RandomFill
	}
	return p.StripSectionsByType(NonEssentialSections, fillMode)
}

// StripExceptionHandlingData removes exception handling data (risky)
func (p *PEFile) StripExceptionHandlingData(useRandomFill bool) error {
	fillMode := ZeroFill
	if useRandomFill {
		fillMode = RandomFill
	}
	return p.StripSectionsByType(ExceptionSections, fillMode)
}

// StripBuildInfoSections removes build information
func (p *PEFile) StripBuildInfoSections(useRandomFill bool) error {
	fillMode := ZeroFill
	if useRandomFill {
		fillMode = RandomFill
	}
	return p.StripSectionsByType(BuildInfoSections, fillMode)
}

// StripAllMetadata removes a wide range of non-essential metadata
func (p *PEFile) StripAllMetadata(useRandomFill bool) error {
	fillMode := ZeroFill
	if useRandomFill {
		fillMode = RandomFill
	}

	// Strip safe sections
	safeSections := []SectionType{
		DebugSections,
		SymbolSections,
		NonEssentialSections,
		BuildInfoSections,
	}

	for _, sectionType := range safeSections {
		if err := p.StripSectionsByType(sectionType, fillMode); err != nil {
			return fmt.Errorf("failed to strip %s: %w",
				sectionMatchers[sectionType].Description, err)
		}
	}

	// Conditionally strip relocations (safer for DLLs)
	if err := p.StripSectionsByType(RelocationSections, fillMode); err != nil {
		return fmt.Errorf("failed to strip relocations: %w", err)
	}

	// Apply obfuscation
	if err := p.RandomizeSectionNames(); err != nil {
		return fmt.Errorf("failed to randomize section names: %w", err)
	}

	return nil
}

// --- File Size Calculation ---

// CalculatePhysicalFileSize computes the actual used file size
func (p *PEFile) CalculatePhysicalFileSize() (uint64, error) {
	if p.PE == nil {
		return 0, fmt.Errorf("PE file not initialized")
	}

	maxSize := uint64(p.SizeOfHeaders)
	for _, s := range p.Sections {
		if s.Size > 0 {
			end := uint64(s.Offset) + uint64(s.Size)
			if end > maxSize {
				maxSize = end
			}
		}
	}

	return maxSize, nil
}
