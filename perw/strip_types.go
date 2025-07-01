package perw

type SectionType int

const (
	DebugSections SectionType = iota
	SymbolSections
	BuildInfoSections
	NonEssentialSections
	ExceptionSections
	RelocationSections
	TLSSections
	CertificateSections
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
	StripForDLL bool
	StripForEXE bool
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
			ExactNames:  []string{".stab", ".stabstr"},
			PrefixNames: []string{".debug", ".zdebug", ".gnu.debuglto_"},
			Description: "debugging information",
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		SymbolSections: {
			ExactNames:  []string{".symtab", ".strtab", ".shstrtab", ".dynsym", ".dynstr", ".hash", ".gnu.hash", ".gnu.version", ".gnu.version_d", ".gnu.version_r", ".interp"},
			PrefixNames: []string{".gnu.linkonce."},
			Description: "symbol table information",
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		RelocationSections: {
			ExactNames:  []string{".reloc"},
			PrefixNames: []string{},
			Description: "base relocation information",
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     true,
			Fill:        ZeroFill,
		},
		TLSSections: {
			ExactNames:  []string{".tls"},
			PrefixNames: []string{},
			Description: "Thread Local Storage sections",
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     true,
			Fill:        ZeroFill,
		},
		NonEssentialSections: {
			ExactNames:  []string{".comment", ".note", ".drectve", ".shared", ".cormeta", ".sxdata", ".edata", ".rsrc", ".gcc_except_table", ".note.gnu.build-id", ".note.ABI-tag", ".note.gnu.gold-version", ".gnu_debuglink", ".gnu_debugaltlink"},
			PrefixNames: []string{".note.", ".gnu.warning.", ".mdebug."},
			Description: "non-essential metadata",
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		ExceptionSections: {
			ExactNames:  []string{".pdata", ".xdata"},
			PrefixNames: []string{".eh_frame"},
			Description: "structured exception handling data",
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     true,
			Fill:        ZeroFill,
		},
		BuildInfoSections: {
			ExactNames:  []string{".buildid", ".gfids", ".giats", ".gljmp", ".textbss", ".go.buildinfo", ".noptrdata", ".typelink", ".itablink", ".gosymtab", ".gopclntab"},
			PrefixNames: []string{".go.", ".gopkg."},
			Description: "build information and toolchain metadata",
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
		CertificateSections: {
			ExactNames:  []string{".certificate"},
			PrefixNames: []string{},
			Description: "certificate information",
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     true,
			Fill:        ZeroFill,
		},
		RuntimeSections: {
			ExactNames:  []string{".rustc", ".rust_eh_personality", ".llvm_addrsig", ".llvm.embedded.object", ".jcr", ".tm_clone_table", ".data.rel.ro"},
			PrefixNames: []string{".rust.", ".llvm.", ".msvcrt.", ".mingw32."},
			StripForDLL: true,
			StripForEXE: true,
			IsRisky:     false,
			Fill:        ZeroFill,
		},
	}
}

func GetRegexStripRules() []RegexStripRule {
	return []RegexStripRule{
		{
			Patterns: []string{
				`Go build ID: "[a-zA-Z0-9/_\-=+]{20,}"`,                    // More specific build ID pattern
				`\bgo\.buildid\b`,                                          // Specific build ID marker
				`\bgo1\.[0-9]{1,2}(\.[0-9]{1,2})?\b`,                       // Go version with word boundaries
				`\b(golang\.org|github\.com/golang)/[a-zA-Z0-9/_\-\.]{5,}`, // Go module paths only (min 5 chars)
			},
			Description: "Go build/runtime markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// GCC / MinGW specific (improved patterns)
		{
			Patterns: []string{
				`\bmingw_[a-zA-Z0-9_]{3,}\b`,                    // MinGW symbols (min 3 chars)
				`\blibgcc[a-zA-Z0-9_]*\.[a-zA-Z0-9]{1,5}\b`,     // libgcc libraries
				`\bgccmain\.[a-zA-Z0-9]{1,5}\b`,                 // GCC main
				`\b__GNUC__\b|\b__GNUG__\b`,                     // GCC compiler macros
				`(?i)\bGCC: \([^)]+\) [0-9]+\.[0-9]+\.[0-9]+\b`, // GCC version strings
			},
			Description: "GCC/MinGW compiler markers (improved)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// C++ specific markers
		{
			Patterns: []string{
				`\b__cplusplus\b`,
				`\btypeinfo for [a-zA-Z0-9_:]{3,}\b`,
				`\bvtable for [a-zA-Z0-9_:]{3,}\b`,
			},
			Description: "C++ specific markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Rust specific markers (improved and safer)
		{
			Patterns: []string{
				`\brustc [0-9]+\.[0-9]+\.[0-9]+\b`,
				`\bcore::panic::[a-zA-Z0-9_]+\b`,
			},
			Description: "Rust specific markers (safe)",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// .NET/C# specific markers (Safer, non-functional metadata)
		{
			Patterns: []string{
				// PDB (Program Database) file paths. Purely for debugging.
				`(?i)[a-z]:\\[^\s\x00:"*?<>|]+\.pdb`, // Windows PDB path: C:\...\project.pdb
				`(?i)/[^\s\x00:"*?<>|]+\.pdb`,        // Unix PDB path: /home/.../project.pdb
				`\b[a-zA-Z0-9_]+\.pdb\b`,             // Just the PDB filename

				// Source code file paths embedded for stack traces.
				`(?i)[a-z]:\\[^\s\x00:"*?<>|]+\.(cs|vb|fs)`, // Windows source path: C:\...\MyClass.cs
				`(?i)/[^\s\x00:"*?<>|]+\.(cs|vb|fs)`,        // Unix source path: /home/.../MyClass.cs

				// Assembly informational strings containing build metadata (like Git hashes).
				// This is much safer than stripping a generic version string.
				`\b[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9\-.]+)?\+[a-f0-9]{7,40}\b`, // Catches "1.2.3-beta+a1b2c3d4"

				// Default namespace from templates that is often left unchanged.
				// RISCHIO BASSO, ma non nullo. Da usare con cautela.
				// `\b(ConsoleApp|WindowsFormsApp|WebApp)[0-9]*\b`,
			},
			Description: "Safer .NET/C# markers (debug paths, source files, build metadata)",
			Fill:        ZeroFill,
			IsRisky:     false, // These are considered safe as they target non-executable metadata.
		},
		// User/Host specific identifiers
		{
			Patterns: []string{
				`(?i)build@([a-zA-Z0-9\-]+)`,        // Es: build@builder-hostname
				`C:\\Users\\[a-zA-Z0-9_\-\.]{3,}\\`, // Es: C:\Users\john.doe\
				`/home/[a-zA-Z0-9_\-\.]{3,}/`,       // Es: /home/john.doe/
			},
			Description: "User and hostname identifiers from build environment",
			Fill:        ZeroFill,
			IsRisky:     false,
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
				`[0-9]\.[0-9]{2}\s+UPX!`,           // UPX version signature
				`UPX![0-9\.\x00-\x20]{1,10}`,       // UPX signature
				`\$UPX: [a-zA-Z0-9._\-\s]{5,}\$`,   // UPX marker string
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
				// Windows-style paths (C:\Users\..., D:\a\1\s\...)
				`[A-Za-z]:\\[\\/](?:Users|home|runner|a)[\\/][^\s\x00"]+?\.(?:go|c|cpp|h|hpp|rs|cs|vb)`,
				// Unix-style paths (/home/user/..., /usr/local/go/...)
				`/(?:home|Users|usr|opt|var|runner)/[^\s\x00"]+?\.(?:go|c|cpp|h|hpp|rs|cs|vb)`,
				// Go-specific module paths in cache
				`\b(?:GOPATH|GOCACHE|GOROOT)\b`,
				`/go/pkg/mod/[^\s\x00"]+`,
				// Rust cargo paths
				`/\.cargo/registry/src/[^\s\x00"]+`,
			},
			Description: "Source file paths",
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
		// Common third-party library markers
		{
			Patterns: []string{
				`OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]?\s`, // OpenSSL version
				`\bzlib version [0-9]+\.[0-9]+\b`,        // zlib version
				`libcurl/[0-9]+\.[0-9]+`,                 // libcurl version
			},
			Description: "Common third-party library version strings",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		// Linker and Comment Section Markers
		{
			Patterns: []string{
				`Linker: (LLD|ld.lld|gold) [0-9\.]+`, // Linker version (LLD, gold)
				`Debian [0-9\.\-~]+`,                 // Info di build Debian
			},
			Description: "Linker/toolchain info often found in .comment section",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
	}
}
