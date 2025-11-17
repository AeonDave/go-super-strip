package common

type BinaryTarget uint8

const (
	TargetPEExe BinaryTarget = 1 << iota
	TargetPEDLL
	TargetELFBin
	TargetELFSO

	TargetAllPE  = TargetPEExe | TargetPEDLL
	TargetAllELF = TargetELFBin | TargetELFSO
	TargetAll    = TargetAllPE | TargetAllELF
)

func (t BinaryTarget) Has(target BinaryTarget) bool {
	return t&target != 0
}

type FillKind int

const (
	FillZero FillKind = iota
	FillRandom
)

const (
	SectionKeyDebug        = "debug"
	SectionKeySymbol       = "symbol"
	SectionKeyRelocation   = "relocation"
	SectionKeyTLS          = "tls"
	SectionKeyNonEssential = "non_essential"
	SectionKeyException    = "exception"
	SectionKeyBuildInfo    = "build_info"
	SectionKeyCertificate  = "certificate"
	SectionKeyRuntime      = "runtime"
	SectionKeyResource     = "resource"
	SectionKeyImport       = "import"
	SectionKeyNote         = "note"
	SectionKeyLoader       = "loader"
)

type SectionRuleSpec struct {
	Key         string
	ExactNames  []string
	PrefixNames []string
	Description string
	Fill        FillKind
	IsRisky     bool
	Targets     BinaryTarget
}

func SectionSpecs() []SectionRuleSpec {
	return []SectionRuleSpec{
		{
			Key:         SectionKeyDebug,
			ExactNames:  []string{".stab", ".stabstr"},
			PrefixNames: []string{".debug", ".zdebug", ".gnu.debuglto_"},
			Description: "debugging information",
			Fill:        FillZero,
			Targets:     TargetAll,
		},
		{
			Key: SectionKeySymbol,
			ExactNames: []string{
				".symtab", ".strtab", ".shstrtab",
			},
			PrefixNames: []string{".gnu.linkonce."},
			Description: "symbol table information",
			Fill:        FillZero,
			Targets:     TargetAllPE | TargetELFBin,
		},
		{
			Key:         SectionKeyRelocation,
			ExactNames:  []string{".reloc"},
			PrefixNames: []string{".rel.", ".rela."},
			Description: "relocation information",
			Fill:        FillZero,
			IsRisky:     true,
			Targets:     TargetAllPE | TargetELFBin,
		},
		{
			Key:         SectionKeyTLS,
			ExactNames:  []string{".tls", ".tdata", ".tbss"},
			Description: "thread local storage",
			Fill:        FillZero,
			IsRisky:     true,
			Targets:     TargetAll,
		},
		{
			Key: SectionKeyNonEssential,
			ExactNames: []string{
				".comment", ".note", ".drectve", ".shared", ".sxdata",
				".gcc_except_table", ".note.gnu.build-id", ".note.ABI-tag",
				".note.gnu.gold-version", ".gnu_debuglink", ".gnu_debugaltlink",
			},
			PrefixNames: []string{".note.", ".gnu.warning.", ".mdebug."},
			Description: "non-essential metadata (safe)",
			Fill:        FillZero,
			Targets:     TargetAll,
		},
		{
			Key: SectionKeyException,
			ExactNames: []string{
				".pdata", ".xdata", ".eh_frame", ".eh_frame_hdr", ".gcc_except_table",
			},
			Description: "structured exception handling data",
			Fill:        FillZero,
			IsRisky:     true,
			Targets:     TargetAllPE | TargetELFBin,
		},
		{
			Key: SectionKeyBuildInfo,
			ExactNames: []string{
				".buildid", ".gfids", ".giats", ".gljmp", ".textbss",
				".noptrdata", ".typelink", ".itablink", ".gosymtab", ".gopclntab",
			},
			PrefixNames: []string{".go.", ".gopkg."},
			Description: "build information and toolchain metadata",
			Fill:        FillZero,
			Targets:     TargetAll,
		},
		{
			Key:         SectionKeyCertificate,
			ExactNames:  []string{".certificate"},
			Description: "certificate information",
			Fill:        FillZero,
			IsRisky:     true,
			Targets:     TargetAllPE,
		},
		{
			Key: SectionKeyRuntime,
			ExactNames: []string{
				".rustc", ".rust_eh_personality", ".llvm_addrsig",
				".llvm.embedded.object", ".jcr", ".tm_clone_table",
				".data.rel.ro", ".data.rel.ro.local",
			},
			PrefixNames: []string{".rust.", ".llvm.", ".msvcrt.", ".mingw32."},
			Description: "runtime and compiler-specific sections",
			Fill:        FillZero,
			Targets:     TargetAll,
		},
		{
			Key: SectionKeyResource,
			ExactNames: []string{
				".rsrc", ".rsrc$01", ".rsrc$02", ".rsrc$DATA",
			},
			PrefixNames: []string{".rsrc$"},
			Description: "embedded resources",
			Fill:        FillZero,
			Targets:     TargetAllPE,
		},
		{
			Key: SectionKeyImport,
			ExactNames: []string{
				".idata", ".edata",
			},
			PrefixNames: []string{".idata$"},
			Description: "import/export tables",
			Fill:        FillZero,
			IsRisky:     true,
			Targets:     TargetAllPE,
		},
		{
			Key:         SectionKeyNote,
			ExactNames:  []string{".note"},
			PrefixNames: []string{".note."},
			Description: "ELF note metadata",
			Fill:        FillZero,
			Targets:     TargetAllELF,
		},
		{
			Key: SectionKeyLoader,
			ExactNames: []string{
				".interp", ".dynamic", ".dynsym", ".dynstr", ".gnu.version",
				".gnu.version_r", ".gnu.version_d", ".gnu.hash", ".hash",
				".got", ".got.plt", ".plt", ".plt.got", ".plt.sec",
				".init", ".fini", ".init_array", ".fini_array",
			},
			Description: "loader and dynamic linker metadata",
			Fill:        FillZero,
			IsRisky:     true,
			Targets:     TargetAllELF,
		},
	}
}
