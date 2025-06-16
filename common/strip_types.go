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
)

// FillMode represents the type of data filling
type FillMode int

const (
	ZeroFill FillMode = iota
	RandomFill
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

// GetSectionMatchers returns all section types and their matching rules
func GetSectionMatchers() map[SectionType]SectionMatcher {
	return map[SectionType]SectionMatcher{
		DebugSections: {
			ExactNames: []string{
				".debug", ".debug$S",
				".debug$T", ".debug$P", ".debug$F",
			},
			PrefixNames: []string{".debug$", ".zdebug_", ".debug_"},
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
				".comment", ".note", ".drectve",
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
}
