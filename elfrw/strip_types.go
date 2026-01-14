package elfrw

import "gosstrip/common"

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
	LoaderSections
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

var elfSectionKeyMap = map[string]SectionType{
	common.SectionKeyDebug:        DebugSections,
	common.SectionKeySymbol:       SymbolSections,
	common.SectionKeyBuildInfo:    BuildInfoSections,
	common.SectionKeyNonEssential: NonEssentialSections,
	common.SectionKeyException:    ExceptionSections,
	common.SectionKeyRelocation:   RelocationSections,
	common.SectionKeyTLS:          TLSSections,
	common.SectionKeyNote:         NoteSections,
	common.SectionKeyRuntime:      RuntimeSections,
	common.SectionKeyLoader:       LoaderSections,
}

func mapFill(kind common.FillKind) FillMode {
	if kind == common.FillRandom {
		return RandomFill
	}
	return ZeroFill
}

func getSectionStripRule() map[SectionType]SectionStripRule {
	rules := make(map[SectionType]SectionStripRule)
	for _, spec := range common.SectionSpecs() {
		sectionType, ok := elfSectionKeyMap[spec.Key]
		if !ok {
			continue
		}
		if !(spec.Targets.Has(common.TargetELFBin) || spec.Targets.Has(common.TargetELFSO)) {
			continue
		}
		rule := SectionStripRule{
			ExactNames:  spec.ExactNames,
			PrefixNames: spec.PrefixNames,
			Description: spec.Description,
			StripForSO:  spec.Targets.Has(common.TargetELFSO),
			StripForBIN: spec.Targets.Has(common.TargetELFBin),
			IsRisky:     spec.IsRisky,
			Fill:        mapFill(spec.Fill),
		}
		if sectionType == BuildInfoSections {
			rule.ExactNames = nil
			rule.PrefixNames = []string{".go.", ".gopkg."}
		}
		rules[sectionType] = rule
	}
	return rules
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
			},
			Description: "C++ specific markers",
			Fill:        ZeroFill,
			IsRisky:     false,
		},
		//Rust specific markers
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
		// Packer signatures and markers
		{
			Patterns: []string{
				`[0-9]\.[0-9]{2}\s+UPX!`,                                       // UPX version signature (e.g., 5.02 UPX!)
				`UPX![0-9\.\x00-\x20]{1,10}`,                                   // UPX magic blocks with padding
				`\$UPX: [a-zA-Z0-9._\-\s]{5,}\$`,                               // UPX metadata marker
				`(?i)\$Id:\s*UPX[^$]{10,}\$`,                                   // UPX $Id banner string
				`(?i)http://upx\.sf\.net\s*\$`,                                 // UPX website marker
				`(?i)Info: This file is packed with the UPX executable packer`, // Informational banner
				`(?i)\b(UPX!|PECompact|ASPack|themida|vmprotect)\b`,            // Common packer names
			},
			Description: "Known packer signatures",
			Fill:        RandomFill,
			IsRisky:     false,
		},
		{
			Patterns: []string{
				`(?i)\bclang version [0-9][0-9\.]+\b`,
				`(?i)Microsoft \(R\) (C|C\+\+)`,
				`(?i)\bMSVC\b`,
				`(?i)\bIntel\(R\) (C|C\+\+)`,
			},
			Description: "compiler fingerprint strings (force)",
			Fill:        ZeroFill,
			IsRisky:     true,
		},
		{
			Patterns: []string{
				// NOTE: keep these conservative to avoid wiping legitimate config strings.
				// Email-like patterns are common in user data; keep behind a word boundary.
				`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`,
				// ld.so path fingerprints (common in dynamically linked binaries).
				// This is not strictly necessary for execution, but avoid matching arbitrary file paths.
				`/(?:lib|usr/lib|lib64|usr/lib64)[^"\s\x00]*ld-(?:linux|musl)[^"\s\x00]*`,
			},
			Description: "Contact strings and loader fingerprints",
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
