package common

// SectionType represents the type of section for stripping
type SectionType int

const (
	DebugSections SectionType = iota
	SymbolSections
	RelocationSections
	NonEssentialSections
	ExceptionSections
	BuildInfoSections
	RuntimeSections     // runtime-specific sections
	AggressiveStripping // aggressive stripping mode
)

// FillMode represents the fill mode for stripped data
type FillMode int

const (
	ZeroFill FillMode = iota
	RandomFill
)

type SectionMatcher struct {
	ExactNames        []string
	PrefixNames       []string
	Description       string
	StripForDLL       bool     // True if can be stripped from DLL
	StripForEXE       bool     // True if can be stripped from EXE
	IsRisky           bool     // True if requires -f (force)
	ObfuscationNeeded bool     // True if needed for obfuscation (disables strip/compact if -o)
	Fill              FillMode // ZeroFill or RandomFill
}

// ...existing code...

func GetSectionMatchers() map[SectionType]SectionMatcher {
	return map[SectionType]SectionMatcher{
		DebugSections: {
			ExactNames:        []string{".stab", ".stabstr"},
			PrefixNames:       []string{".debug", ".zdebug", ".gnu.debuglto_"},
			Description:       "debugging information",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false,
			Fill:              ZeroFill,
		},
		SymbolSections: {
			ExactNames:        []string{".symtab", ".strtab", ".shstrtab", ".dynsym", ".dynstr", ".hash", ".gnu.hash", ".gnu.version", ".gnu.version_d", ".gnu.version_r", ".interp"},
			PrefixNames:       []string{".gnu.linkonce."},
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
			IsRisky:           true,
			ObfuscationNeeded: true,
			Fill:              ZeroFill,
		},
		NonEssentialSections: {
			ExactNames:        []string{".comment", ".note", ".drectve", ".shared", ".cormeta", ".sxdata", ".edata", ".idata", ".rsrc", ".tls", ".CRT", ".rdata", ".eh_frame_hdr", ".eh_frame", ".gcc_except_table", ".note.gnu.build-id", ".note.ABI-tag", ".note.gnu.gold-version", ".gnu_debuglink", ".gnu_debugaltlink"},
			PrefixNames:       []string{".note.", ".gnu.warning.", ".mdebug."},
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
		}, BuildInfoSections: {
			ExactNames:        []string{".buildid", ".gfids", ".giats", ".gljmp", ".textbss", ".go.buildinfo", ".noptrdata", ".typelink", ".itablink", ".gosymtab", ".gopclntab"},
			PrefixNames:       []string{".go.", ".gopkg."},
			Description:       "build information and toolchain metadata",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           false,
			ObfuscationNeeded: false,
			Fill:              ZeroFill,
		},
		RuntimeSections: {
			ExactNames:        []string{".rustc", ".rust_eh_personality", ".llvm_addrsig", ".llvm.embedded.object", ".init_array", ".fini_array", ".preinit_array", ".ctors", ".dtors", ".jcr", ".tm_clone_table", ".got", ".got.plt", ".plt", ".plt.got", ".plt.sec", ".data.rel.ro"},
			PrefixNames:       []string{".rust.", ".llvm.", ".msvcrt.", ".mingw32."},
			Description:       "runtime and language-specific sections",
			StripForDLL:       true,
			StripForEXE:       true,
			IsRisky:           true,
			ObfuscationNeeded: true,
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

type RegexStripRule struct {
	Patterns    []string
	Description string
	Fill        FillMode
	IsRisky     bool
}

// GetRegexStripRules returns all regex-based stripping rules
func GetRegexStripRules() []RegexStripRule {
	return []RegexStripRule{
		// Go build/runtime markers
		{
			Patterns: []string{
				`Go build ID: "[a-zA-Z0-9/_\-=+]{20,}"`,   // More specific build ID pattern
				`\bgo\.buildid\b`,                         // Specific build ID marker
				`\bgo1\.[0-9]+(\.[0-9]+)?\b`,              // Go version with word boundaries
				`golang\.org/[a-zA-Z0-9/_\-\.]{5,}`,       // Go module paths only (min 5 chars)
				`/usr/local/go/src/[a-zA-Z0-9/_\-\.]{5,}`, // Go installation paths
				`\btype\.\*[a-zA-Z0-9_\.]+\b`,             // Go type information
				`\bgo\.info\.[a-zA-Z0-9_\.]+\b`,           // Go runtime info
				`runtime\.[a-zA-Z0-9_]+\([^)]*\)`,         // Go runtime function calls
			},
			Description: "Go build/runtime markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// GCC / MinGW specific (improved patterns)
		{
			Patterns: []string{
				`\bmingw_[a-zA-Z0-9_]{3,}\b`,                // MinGW symbols (min 3 chars)
				`\blibgcc[a-zA-Z0-9_]*\.[a-zA-Z0-9]{1,5}\b`, // libgcc libraries
				`\bgccmain\.[a-zA-Z0-9]{1,5}\b`,             // GCC main
				`\b__GNUC__\b|\b__GNUG__\b`,                 // GCC compiler macros
				`\bGCC: \([^)]+\) [0-9]+\.[0-9]+\.[0-9]+\b`, // GCC version strings
			},
			Description: "GCC/MinGW compiler markers (improved)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// C++ specific markers
		{
			Patterns: []string{
				`\b__cplusplus\b`,                    // C++ standard macro
				`\bstd::[a-zA-Z0-9_:]{3,}\b`,         // C++ standard library (min 3 chars)
				`\b__cxa_[a-zA-Z0-9_]+\b`,            // C++ ABI functions
				`\btypeinfo for [a-zA-Z0-9_:]{3,}\b`, // C++ typeinfo
				`\bvtable for [a-zA-Z0-9_:]{3,}\b`,   // C++ vtables
				`\b_Z[a-zA-Z0-9_]{5,}\b`,             // C++ mangled names (min 5 chars)
			},
			Description: "C++ specific markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Rust specific markers (improved and safer)
		{
			Patterns: []string{
				`\brust_[a-zA-Z0-9_]{3,}\b`,        // Rust symbols (min 3 chars)
				`\brustc [0-9]+\.[0-9]+\.[0-9]+\b`, // Rust compiler version
				`\b_ZN[0-9]+[a-zA-Z0-9_]{10,}\b`,   // Rust mangled names (min 10 chars)
				`\bcore::panic::[a-zA-Z0-9_]+\b`,   // Rust core panic
				`\balloc::[a-zA-Z0-9_:]{5,}\b`,     // Rust allocator
				`\bstd::rt::[a-zA-Z0-9_]+\b`,       // Rust standard runtime
			},
			Description: "Rust specific markers (safe)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// .NET/C# specific markers
		{
			Patterns: []string{
				`\b\.NET Framework [0-9]+\.[0-9]+\b`,        // .NET Framework version
				`\b\.NET [0-9]+\.[0-9]+\b`,                  // .NET version
				`\bSystem\.[A-Za-z][a-zA-Z0-9_\.]{5,}\b`,    // .NET System namespaces
				`\bMicrosoft\.[A-Za-z][a-zA-Z0-9_\.]{5,}\b`, // Microsoft namespaces
				`\bmscorlib\b|\bSystem\.Private\.CoreLib\b`, // .NET core libraries
				`\b_CorExeMain\b|\b_CorDllMain\b`,           // .NET entry points
			},
			Description: ".NET/C# runtime markers",
			Fill:        ZeroFill,
			IsRisky:     true, // Should not be in Go files
		},
		// Build metadata and version strings (improved safety)
		{
			Patterns: []string{
				`\$Id: [a-zA-Z0-9._\-\s/]{10,}\$`,        // CVS/SVN ID tags (min 10 chars)
				`@\(#\)[a-zA-Z0-9._\-\s]{10,}`,           // SCCS what strings (min 10 chars)
				`\b__DATE__\b|\b__TIME__\b|\b__FILE__\b`, // Compiler macros (exact match)
				`\bbuild-[a-zA-Z0-9\-]{8,40}\b`,          // Build identifiers (8-40 chars)
				`\bcommit-[a-f0-9]{7,40}\b`,              // Git commit IDs (7-40 chars)
				`\bversion [0-9]+\.[0-9]+\.[0-9]+\b`,     // Version strings
			},
			Description: "Build metadata and version strings (safe)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Packer/Compressor signatures (more comprehensive)
		{
			Patterns: []string{
				`UPX![0-9\.\x00-\x20]{1,10}`,       // UPX signature
				`\$UPX: [a-zA-Z0-9._\-\s]{5,}\$`,   // UPX marker string
				`[0-9]\.[0-9]{2}\s+UPX!`,           // UPX version signature
				`\bPECompact\b|\bASPack\b|\bUPX\b`, // Known packers
				`\bthemida\b|\bvmprotect\b`,        // Protection software
			},
			Description: "Known packer signatures (comprehensive)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Source file paths (safer and more comprehensive)
		{
			Patterns: []string{
				`[A-Za-z]:\\[Uu]sers\\[^\\]{3,}\\[Gg]o\\src\\[^\s\x00]{10,}\.go`, // Windows Go source (min lengths)
				`[A-Za-z]:\\[Pp]rogram [Ff]iles\\[Gg]o\\src\\[^\s\x00]{10,}\.go`, // Windows Go install
				`/usr/local/go/src/[a-zA-Z0-9/_\-\.]{10,}\.go`,                   // Unix Go install
				`/home/[a-zA-Z0-9_\-]{3,}/go/src/[^\s\x00]{10,}\.go`,             // Unix Go workspace
				`[A-Za-z]:\\[^\\]{5,}\\[^\\]{3,}\.rs`,                            // Rust source files
				`[A-Za-z]:\\[^\\]{5,}\\[^\\]{3,}\.(cpp|cxx|cc|c)\b`,              // C/C++ source files
			},
			Description: "Source file paths (safe with minimum lengths)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Build environment and toolchain info (safer)
		{
			Patterns: []string{
				`(?i)compiled\s+by\s+[a-zA-Z0-9._\-\s]{5,40}`,          // Compiled by (limited length)
				`(?i)compiler version\s+[0-9]+\.[0-9]+[^\n\x00]{0,20}`, // Compiler version
				`(?i)build id\s+[a-zA-Z0-9\-]{8,40}`,                   // Build ID
				`(?i)linker version\s+[0-9]+\.[0-9]+`,                  // Linker version
				`(?i)assembler version\s+[0-9]+\.[0-9]+`,               // Assembler version
			},
			Description: "Build environment hints (length-limited)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Debug and profiling info
		{
			Patterns: []string{
				`\b[a-zA-Z0-9_]+\.pdb\b`,        // PDB debug files
				`\b[a-zA-Z0-9_]+\.dwarf\b`,      // DWARF debug info
				`\bDWARF version [0-9]+\b`,      // DWARF version
				`\bstabs\b|\bstabstr\b`,         // STABS debug format
				`\b__func__\b|\b__FUNCTION__\b`, // Function name macros
				`\b__LINE__\b`,                  // Line number macro
			},
			Description: "Debug and profiling information",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
	}
}
