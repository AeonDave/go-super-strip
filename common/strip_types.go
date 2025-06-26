package common

// SectionType rappresenta il tipo di sezione per lo stripping
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

// FillMode rappresenta la modalità di riempimento dei dati strippati
type FillMode int

const (
	ZeroFill FillMode = iota
	RandomFill
)

// SectionMatcher contiene le regole di matching e le policy di stripping
type SectionMatcher struct {
	ExactNames        []string
	PrefixNames       []string
	Description       string
	StripForDLL       bool     // True se può essere strippata da DLL
	StripForEXE       bool     // True se può essere strippata da EXE
	IsRisky           bool     // True se serve -f (force)
	ObfuscationNeeded bool     // True se serve per obfuscation (inibisce strip/compact se -o)
	Fill              FillMode // ZeroFill o RandomFill
}

// GetSectionMatchers restituisce tutte le regole di matching per tipo sezione
func GetSectionMatchers() map[SectionType]SectionMatcher {
	return map[SectionType]SectionMatcher{
		DebugSections: {
			ExactNames:        []string{},
			PrefixNames:       []string{".debug", ".zdebug"},
			Description:       "debugging information",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false,
			Fill:              ZeroFill,
		},
		SymbolSections: {
			ExactNames:        []string{".symtab"},
			PrefixNames:       []string{},
			Description:       "symbol table information",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false,
			Fill:              ZeroFill,
		},
		RelocationSections: {
			ExactNames:        []string{".reloc"},
			PrefixNames:       []string{},
			Description:       "base relocation information",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           true, // Fixed: Relocation stripping is risky!
			ObfuscationNeeded: true,
			Fill:              ZeroFill,
		},
		NonEssentialSections: {
			ExactNames:        []string{".comment", ".note", ".drectve", ".shared", ".cormeta", ".sxdata", ".edata"},
			PrefixNames:       []string{},
			Description:       "non-essential metadata",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false,
			Fill:              ZeroFill,
		},
		ExceptionSections: {
			ExactNames:        []string{".pdata", ".xdata"},
			PrefixNames:       []string{},
			Description:       "structured exception handling data",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           true,
			ObfuscationNeeded: true,
			Fill:              ZeroFill,
		},
		BuildInfoSections: {
			ExactNames:        []string{".buildid", ".gfids", ".giats", ".gljmp", ".textbss"},
			PrefixNames:       []string{},
			Description:       "build information and toolchain metadata",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false,
			Fill:              ZeroFill,
		},
		AggressiveStripping: {
			ExactNames:        []string{".bss"},
			PrefixNames:       []string{},
			Description:       "uninitialized data sections",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false,
			Fill:              RandomFill,
		},
	}
}

// RegexStripRule definisce una regola per stripping tramite regex
type RegexStripRule struct {
	Patterns    []string // Espressioni regolari da applicare (gruppate logicamente)
	Description string   // Descrizione della regola
	Fill        FillMode // ZeroFill o RandomFill
	IsRisky     bool     // True se serve -f
}

// GetRegexStripRules restituisce tutte le regole di stripping tramite regex
func GetRegexStripRules() []RegexStripRule {
	return []RegexStripRule{
		// Go build/runtime markers (conservative)
		{
			Patterns: []string{
				`Go build ID: "[^"]*"`,                 // Safe: exact build ID pattern
				`\bgo\.buildid\b`,                      // Safe: specific build ID marker
				`\bgo1\.[0-9]+(\.[0-9]+)?\b`,           // Safe: Go version with word boundaries
				`golang\.org/[a-zA-Z0-9/_\-\.]+`,       // Safe: Go module paths only
				`/usr/local/go/src/[a-zA-Z0-9/_\-\.]+`, // Safe: specific Go installation paths
			},
			Description: "Go build/runtime markers (conservative)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// GCC / MinGW specific
		{
			Patterns: []string{
				`(?i)\bmingw_[a-zA-Z0-9_]*\b`,
				`(?i)mingw_[a-zA-Z0-9_]*[.]?`,
				`(?i)libgcc[a-zA-Z0-9_]*\.[a-zA-Z0-9]+`,
				`(?i)gccmain\.[a-zA-Z0-9]+`,
			},
			Description: "GCC/MinGW compiler markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Microsoft C/C++ runtime markers (marked as risky for Go files)
		{
			Patterns: []string{
				`\bmsvc\b|\bmsvcr\b|\bmsvcp\b|\bucrtbase\b|\bvcruntime\b`,
			},
			Description: "Microsoft C/C++ runtime markers",
			Fill:        ZeroFill,
			IsRisky:     true, // Risky for Go files
		},
		// Python runtime markers (not for Go files)
		{
			Patterns: []string{
				`\bpython\b|\bpyinit\b|\bpyobject\b`,
			},
			Description: "Python runtime markers",
			Fill:        ZeroFill,
			IsRisky:     true, // Should not be in Go files
		},
		// Java/JVM runtime markers (not for Go files)
		{
			Patterns: []string{
				`\bjava\b|\bjvm\b|\bjni\b`,
			},
			Description: "Java/JVM runtime markers",
			Fill:        ZeroFill,
			IsRisky:     true, // Should not be in Go files
		},
		// Delphi/Pascal runtime markers (not for Go files)
		{
			Patterns: []string{
				`\bdelphi\b|\bborland\b|\bcodegear\b|\bembarcadero\b`,
			},
			Description: "Delphi/Pascal runtime markers",
			Fill:        ZeroFill,
			IsRisky:     true, // Should not be in Go files
		},
		// Rust runtime markers (not for Go files)
		{
			Patterns: []string{
				`\brust_\b|\brustc\b|\bstd::panic\b|\bcore::panic\b`,
			},
			Description: "Rust runtime markers",
			Fill:        ZeroFill,
			IsRisky:     true, // Should not be in Go files
		},
		// Build metadata and version strings (safe patterns only)
		{
			Patterns: []string{
				`\$Id: [^$]+\$`,            // CVS/SVN ID tags
				`@\(#\)[a-zA-Z0-9._\-\s]+`, // SCCS what strings
				`__DATE__`,                 // Compiler macros
				`__TIME__`,
				`__FILE__`,
				`\bbuild-[a-zA-Z0-9\-]{8,}\b`, // Build identifiers with minimum length
				`\bcommit-[a-f0-9]{7,40}\b`,   // Git commit IDs
			},
			Description: "Build metadata and version strings (safe patterns)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Packer/Compressor signatures (specific patterns only)
		{
			Patterns: []string{
				`UPX![0-9\.\x00-\x20]{1,10}`, // Specific UPX signature
				`\$UPX: [^$]+\$`,             // UPX marker string
				`[0-9]\.[0-9]{2}\s+UPX!`,     // UPX version signature like "4.21 UPX!"
			},
			Description: "Known packer signatures (conservative)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Source file paths (conservative matching)
		{
			Patterns: []string{
				`[A-Za-z]:\\[Uu]sers\\[^\\]+\\[Gg]o\\src\\[^\s\x00]+\.go`,    // Windows Go source paths
				`[A-Za-z]:\\[Pp]rogram [Ff]iles\\[Gg]o\\src\\[^\s\x00]+\.go`, // Windows Go installation paths
				`/usr/local/go/src/[a-zA-Z0-9/_\-\.]+\.go`,                   // Unix Go installation paths
				`/home/[a-zA-Z0-9_\-]+/go/src/[^\s\x00]+\.go`,                // Unix Go workspace paths
			},
			Description: "Go source file paths (conservative)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Build environment hints
		{
			Patterns: []string{
				`(?i)compiled\s+by[^\n\x00]*`,
				`(?i)compiler version[^\n\x00]*`,
				`(?i)build id[^\n\x00]*`,
			},
			Description: "Build environment hints",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
	}
}
