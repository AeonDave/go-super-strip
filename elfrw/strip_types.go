package elfrw

type SectionType int

const (
	DebugSections SectionType = iota
	SymbolSections
	BuildInfoSections
	NonEssentialSections
	ExceptionSections
	RelocationSections
	TLSSections
	NoteSections
	RuntimeSections
)

type FillMode int

const (
	ZeroFill FillMode = iota
	RandomFill
)

type SectionStripRule struct {
	ExactNames  []string
	PrefixNames []string
	Description string
	StripForSO  bool // Shared object (.so)
	StripForBIN bool // Executable
	IsRisky     bool
	Fill        FillMode
}

type RegexStripRule struct {
	Patterns    []string
	Description string
	Fill        FillMode
	IsRisky     bool
}

func GetSectionStripRule() map[SectionType]SectionStripRule {
	return map[SectionType]SectionStripRule{
		DebugSections: {
			ExactNames:  []string{},
			PrefixNames: []string{".debug", ".zdebug"},
			Description: "debugging information",
			StripForSO:  true,
			StripForBIN: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		SymbolSections: {
			ExactNames:  []string{".symtab", ".strtab"},
			PrefixNames: []string{},
			Description: "symbol table information",
			StripForSO:  false, // Keep for shared objects as they may be needed
			StripForBIN: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		RelocationSections: {
			ExactNames:  []string{},
			PrefixNames: []string{".rel.", ".rela."},
			Description: "relocation information",
			StripForSO:  false, // Very risky for shared objects
			StripForBIN: true,  // Can be risky for executables too
			IsRisky:     true,
			Fill:        ZeroFill,
		},
		TLSSections: {
			ExactNames:  []string{".tdata", ".tbss"},
			PrefixNames: []string{},
			Description: "Thread Local Storage sections",
			StripForSO:  false,
			StripForBIN: false, // TLS is often essential
			IsRisky:     true,
			Fill:        ZeroFill,
		},
		NonEssentialSections: {
			ExactNames:  []string{".comment", ".gnu_debuglink", ".gnu_debugaltlink"},
			PrefixNames: []string{".note.", ".gnu.warning"},
			Description: "non-essential metadata",
			StripForSO:  true,
			StripForBIN: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		ExceptionSections: {
			ExactNames:  []string{".eh_frame", ".eh_frame_hdr", ".gcc_except_table"},
			PrefixNames: []string{},
			Description: "exception handling data",
			StripForSO:  false, // Exception handling often needed in shared libs
			StripForBIN: true,  // Can be risky for executables with C++
			IsRisky:     true,
			Fill:        ZeroFill,
		},
		BuildInfoSections: {
			ExactNames:  []string{""},
			PrefixNames: []string{".go.", ".gopkg."},
			Description: "build information and toolchain metadata",
			StripForSO:  true,
			StripForBIN: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		NoteSections: {
			ExactNames:  []string{".note"},
			PrefixNames: []string{".note."},
			Description: "note sections with metadata",
			StripForSO:  true,
			StripForBIN: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		RuntimeSections: {
			ExactNames:  []string{".rustc", ".rust_eh_personality", ".llvm_addrsig", ".llvm.embedded.object", ".jcr", ".tm_clone_table", ".data.rel.ro.local"},
			PrefixNames: []string{".rust.", ".llvm."},
			Description: "runtime and compiler-specific sections",
			StripForSO:  true,
			StripForBIN: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
	}
}

func GetRegexStripRules() []RegexStripRule {
	return []RegexStripRule{
		{
			Patterns: []string{
				`Go build ID: "[a-zA-Z0-9/_\-=+]{20,}"`,                    // Go build ID pattern
				`\bgo\.buildid\b`,                                          // Build ID marker
				`\bgo1\.[0-9]{1,2}(\.[0-9]{1,2})?\b`,                       // Go version
				`\b(golang\.org|github\.com/golang)/[a-zA-Z0-9/_\-\.]{5,}`, // Go module paths
			},
			Description: "Go build/runtime markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// GCC / GNU toolchain specific
		{
			Patterns: []string{
				`\bGCC: \([^)]+\) [0-9]+\.[0-9]+\.[0-9]+\b`, // GCC version strings
				`\b__GNUC__\b|\b__GNUG__\b`,                 // GCC compiler macros
				`\bgnu_debuglink\b`,                         // GNU debug link
				`(?i)\bGNU [a-zA-Z]+ [0-9]+\.[0-9]+\b`,      // GNU tools version
			},
			Description: "GCC/GNU toolchain markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// C++ specific markers
		{
			Patterns: []string{
				`\b__cplusplus\b`,
				`\btypeinfo for [a-zA-Z0-9_:]{3,}\b`,
				`\bvtable for [a-zA-Z0-9_:]{3,}\b`,
				`\b_Z[a-zA-Z0-9_]+\b`, // Mangled C++ symbols (basic pattern)
			},
			Description: "C++ specific markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Rust specific markers
		{
			Patterns: []string{
				`\brustc [0-9]+\.[0-9]+\.[0-9]+\b`,
				`\bcore::panic::[a-zA-Z0-9_]+\b`,
				`\brust_begin_unwind\b`,
				`\brust_eh_personality\b`,
			},
			Description: "Rust specific markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Source file paths
		{
			Patterns: []string{
				// Unix-style paths
				`/(?:home|Users|usr|opt|var|tmp)/[^\s\x00"]+?\.(?:go|c|cpp|h|hpp|rs|cs|vb|py)`,
				// Build environment paths
				`/(?:build|src|work)/[^\s\x00"]+`,
				// Go-specific paths
				`/go/pkg/mod/[^\s\x00"]+`,
				`\b(?:GOPATH|GOCACHE|GOROOT)\b`,
				// Rust cargo paths
				`/\.cargo/registry/src/[^\s\x00"]+`,
			},
			Description: "Source file paths and build environment",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Build metadata and version strings
		{
			Patterns: []string{
				`\$Id: [a-zA-Z0-9._\-\s/]{10,}\$`,        // CVS/SVN ID tags
				`@\(#\)[a-zA-Z0-9._\-\s]{10,}`,           // SCCS what strings
				`\b__DATE__\b|\b__TIME__\b|\b__FILE__\b`, // Compiler macros
				`\bbuild-[a-zA-Z0-9\-]{8,40}\b`,          // Build identifiers
				`\bcommit-[a-f0-9]{7,40}\b`,              // Git commit IDs
				`\bversion [0-9]+\.[0-9]+\.[0-9]+\b`,     // Version strings
			},
			Description: "Build metadata and version strings",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// User/Host specific identifiers
		{
			Patterns: []string{
				`(?i)build@([a-zA-Z0-9\-]+)`,  // Build hostname
				`/home/[a-zA-Z0-9_\-\.]{3,}/`, // User home paths
				`/tmp/[a-zA-Z0-9_\-\.]{3,}/`,  // Temp directories
			},
			Description: "User and hostname identifiers from build environment",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Debug and profiling info
		{
			Patterns: []string{
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
		// Common library markers
		{
			Patterns: []string{
				`glibc [0-9]+\.[0-9]+`,                   // glibc version
				`musl libc [0-9]+\.[0-9]+`,               // musl version
				`OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]?\s`, // OpenSSL version
				`\bzlib version [0-9]+\.[0-9]+\b`,        // zlib version
				`libcurl/[0-9]+\.[0-9]+`,                 // libcurl version
			},
			Description: "Common library version strings",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Linker and toolchain info
		{
			Patterns: []string{
				`Linker: (LLD|ld\.lld|gold|ld\.bfd) [0-9\.]+`, // Linker version
				`collect2 version [0-9\.]+`,                   // GNU collect2
				`GNU ld \([^)]+\) [0-9\.]+`,                   // GNU linker
			},
			Description: "Linker/toolchain info",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
	}
}
