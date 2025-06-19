package common

// SectionType represents the type of sections for stripping
type SectionType int

const (
	DebugSections SectionType = iota
	SymbolSections
	RelocationSections
	NonEssentialSections
	ExceptionSections
	BuildInfoSections
	AggressiveStripping // New aggressive stripping mode
)

// FillMode represents the type of data filling
type FillMode int

const (
	ZeroFill FillMode = iota
	RandomFill
)

// SectionMatcher holds section matching rules
type SectionMatcher struct {
	ExactNames        []string
	PrefixNames       []string
	Description       string
	StripForDLL       bool // Whether to strip for DLL files
	StripForEXE       bool // Whether to strip for EXE files
	IsRisky           bool // Whether stripping might break functionality
	ObfuscationNeeded bool // Whether these sections are needed for obfuscation
}

// GetSectionMatchers returns all section types and their matching rules
func GetSectionMatchers() map[SectionType]SectionMatcher {
	return map[SectionType]SectionMatcher{
		DebugSections: {
			ExactNames: []string{
				".debug", ".debug$S",
				".debug$T", ".debug$P", ".debug$F",
			},
			PrefixNames:       []string{".debug$", ".zdebug_", ".debug_"},
			Description:       "debugging information",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false, // Debug info not needed for obfuscation
		},
		SymbolSections: {
			ExactNames:        []string{}, // PE files typically don't have .symtab
			PrefixNames:       []string{},
			Description:       "symbol table information",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false, // Symbol tables not needed for obfuscation
		},
		RelocationSections: {
			ExactNames:        []string{".reloc"},
			PrefixNames:       []string{},
			Description:       "base relocation information",
			StripForDLL:       true,
			StripForEXE:       true,  // Made aggressive
			IsRisky:           false, // Made less conservative
			ObfuscationNeeded: true,  // Relocation table may be needed for obfuscation
		},
		NonEssentialSections: {
			ExactNames: []string{
				".comment", ".note", ".drectve",
				".shared", ".cormeta", ".sxdata",
				".edata", // export data - can be risky but usually OK
				// Removed .CRT and .tls - they are CRITICAL for C runtime initialization
			},
			PrefixNames:       []string{},
			Description:       "non-essential metadata",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false, // Non-essential sections not needed for obfuscation
		},
		ExceptionSections: {
			ExactNames:        []string{".pdata", ".xdata"},
			PrefixNames:       []string{},
			Description:       "structured exception handling data",
			StripForDLL:       true, // Try stripping again - test if breaks functionality
			StripForEXE:       true, // Try stripping again - test if breaks functionality
			IsRisky:           true, // Keep as risky but allow stripping
			ObfuscationNeeded: true, // Exception handling data may be needed for obfuscation
		},
		BuildInfoSections: {
			ExactNames: []string{
				".buildid", ".gfids", ".giats", ".gljmp", ".textbss",
			},
			PrefixNames:       []string{},
			Description:       "build information and toolchain metadata",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false, // Build info not needed for obfuscation
		},
		AggressiveStripping: {
			ExactNames: []string{
				".bss", // BSS section (uninitialized data)
			},
			PrefixNames:       []string{},
			Description:       "uninitialized data sections",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false, // BSS sections not needed for obfuscation
		},
	}
}
