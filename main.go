package main

import (
	"flag"
	"fmt"
	"gosstrip/elfrw"
	"os"
	"path/filepath"
)

const (
	programName    = "go-sstrip"
	programVersion = "1.0.0"
)

var (
	doZeroTrunc = flag.Bool("z", false, "Also remove trailing zero bytes")
	showHelp    = flag.Bool("help", false, "Show help and exit")
	showVersion = flag.Bool("version", false, "Show version information and exit")

	// Stripping flags (short and long)
	flagStripSectionTable     = flag.Bool("s", false, "Remove the section table (header)")
	flagStripSectionTableLong = flag.Bool("stripSectionTable", false, "Remove the section table (header)")
	flagStripDebug            = flag.Bool("d", false, "Remove debug sections")
	flagStripDebugLong        = flag.Bool("stripDebug", false, "Remove debug sections")
	flagStripSymbols          = flag.Bool("y", false, "Remove symbol tables")
	flagStripSymbolsLong      = flag.Bool("stripSymbols", false, "Remove symbol tables")
	flagStripStrings          = flag.Bool("t", false, "Remove string tables")
	flagStripStringsLong      = flag.Bool("stripStrings", false, "Remove string tables")
	flagStripNonLoad          = flag.Bool("n", false, "Remove non-loadable segments")
	flagStripNonLoadLong      = flag.Bool("stripNonLoadable", false, "Remove non-loadable segments")
	flagRandomNames           = flag.Bool("r", false, "Randomize section names")
	flagRandomNamesLong       = flag.Bool("randomizeNames", false, "Randomize section names")
	flagStripBuildInfo        = flag.Bool("b", false, "Remove build/toolchain info sections")
	flagStripBuildInfoLong    = flag.Bool("stripBuildInfo", false, "Remove build/toolchain info sections")
	flagStripProfiling        = flag.Bool("p", false, "Remove profiling/statistics sections")
	flagStripProfilingLong    = flag.Bool("stripProfiling", false, "Remove profiling/statistics sections")
	flagStripException        = flag.Bool("e", false, "Remove exception/stack unwinding sections")
	flagStripExceptionLong    = flag.Bool("stripException", false, "Remove exception/stack unwinding sections")
	flagStripArch             = flag.Bool("a", false, "Remove architecture-specific sections")
	flagStripArchLong         = flag.Bool("stripArch", false, "Remove architecture-specific sections")
	flagStripPLTReloc         = flag.Bool("l", false, "Remove PLT/relocation sections")
	flagStripPLTRelocLong     = flag.Bool("stripPLTReloc", false, "Remove PLT/relocation sections")
	flagStripAll              = flag.Bool("A", false, "Apply all stripping techniques")
	flagStripAllLong          = flag.Bool("stripAll", false, "Apply all stripping techniques")
)

// Alternative version for --zeroes
func init() {
	flag.BoolVar(doZeroTrunc, "zeroes", false, "Also remove trailing zero bytes")
}

func printHelp() {
	fmt.Printf("Usage: %s [OPTIONS] FILE...\n", programName)
	fmt.Println("Removes all non-essential bytes from ELF executable files.")
	fmt.Println("  -z, --zeroes        Also remove trailing zero bytes.")
	fmt.Println("  -s, --stripSectionTable   Remove the section table (header).")
	fmt.Println("  -d, --stripDebug          Remove debug sections.")
	fmt.Println("  -y, --stripSymbols        Remove symbol tables.")
	fmt.Println("  -t, --stripStrings        Remove string tables.")
	fmt.Println("  -n, --stripNonLoadable    Remove non-loadable segments.")
	fmt.Println("  -r, --randomizeNames      Randomize section names.")
	fmt.Println("  -b, --stripBuildInfo      Remove build/toolchain info sections.")
	fmt.Println("  -p, --stripProfiling      Remove profiling/statistics sections.")
	fmt.Println("  -e, --stripException      Remove exception/stack unwinding sections.")
	fmt.Println("  -a, --stripArch           Remove architecture-specific sections.")
	fmt.Println("  -l, --stripPLTReloc       Remove PLT/relocation sections.")
	fmt.Println("  -A, --stripAll            Apply all stripping techniques.")
	fmt.Println("      --help          Show help and exit.")
	fmt.Println("      --version       Show version information and exit.")
}

func printVersion() {
	fmt.Printf("%s, version %s\n", programName, programVersion)
	fmt.Println("Copyright (C) 2025")
	fmt.Println("License GPLv2+: GNU GPL version 2 or later.")
	fmt.Println("This is free software; you are free to modify and redistribute it.")
	fmt.Println("There is NO WARRANTY, to the extent permitted by law.")
}

func anyFlag(flags ...*bool) bool {
	for _, f := range flags {
		if f != nil && *f {
			return true
		}
	}
	return false
}

func processFile(filename string) error {
	file, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := elfrw.ReadELF(file)
	if err != nil {
		return fmt.Errorf("not a valid ELF file: %w", err)
	}

	if !elfFile.IsExecutableOrShared() {
		return fmt.Errorf("not an executable or shared library")
	}

	// Strip all if requested
	if anyFlag(flagStripAll, flagStripAllLong) {
		if err := elfFile.StripAllMetadata(); err != nil {
			return fmt.Errorf("error stripping all metadata: %w", err)
		}
	}

	// Individual options
	if anyFlag(flagStripSectionTable, flagStripSectionTableLong) {
		if err := elfFile.StripSectionTable(); err != nil {
			return fmt.Errorf("error removing section table: %w", err)
		}
	}
	if anyFlag(flagStripDebug, flagStripDebugLong) {
		if err := elfFile.StripSectionsByNames(elfrw.DebugSectionsExact, false); err != nil {
			return fmt.Errorf("error removing debug sections: %w", err)
		}
		if err := elfFile.StripSectionsByNames(elfrw.DebugSectionsPrefix, true); err != nil {
			return fmt.Errorf("error removing debug sections: %w", err)
		}
	}
	if anyFlag(flagStripSymbols, flagStripSymbolsLong) {
		if err := elfFile.StripSectionsByNames(elfrw.SymbolsSectionsExact, false); err != nil {
			return fmt.Errorf("error removing symbol tables: %w", err)
		}
	}
	if anyFlag(flagStripStrings, flagStripStringsLong) {
		if err := elfFile.StripSectionsByNames(elfrw.StringSectionsExact, false); err != nil {
			return fmt.Errorf("error removing string tables: %w", err)
		}
	}
	if anyFlag(flagStripNonLoad, flagStripNonLoadLong) {
		if err := elfFile.StripNonLoadable(); err != nil {
			return fmt.Errorf("error removing non-loadable segments: %w", err)
		}
	}
	if anyFlag(flagRandomNames, flagRandomNamesLong) {
		if err := elfFile.RandomizeSectionNames(); err != nil {
			return fmt.Errorf("error randomizing section names: %w", err)
		}
	}
	if anyFlag(flagStripBuildInfo, flagStripBuildInfoLong) {
		if err := elfFile.StripSectionsByNames(elfrw.BuildInfoSectionsExact, false); err != nil {
			return fmt.Errorf("error removing build/toolchain info: %w", err)
		}
		if err := elfFile.StripSectionsByNames(elfrw.BuildInfoSectionsPrefix, true); err != nil {
			return fmt.Errorf("error removing build/toolchain info: %w", err)
		}
	}
	if anyFlag(flagStripProfiling, flagStripProfilingLong) {
		if err := elfFile.StripSectionsByNames(elfrw.ProfilingSectionsExact, false); err != nil {
			return fmt.Errorf("error removing profiling/statistics sections: %w", err)
		}
	}
	if anyFlag(flagStripException, flagStripExceptionLong) {
		if err := elfFile.StripSectionsByNames(elfrw.ExceptionSectionsExact, false); err != nil {
			return fmt.Errorf("error removing exception/stack unwinding sections: %w", err)
		}
	}
	if anyFlag(flagStripArch, flagStripArchLong) {
		if err := elfFile.StripSectionsByNames(elfrw.ArchSectionsPrefix, true); err != nil {
			return fmt.Errorf("error removing architecture-specific sections: %w", err)
		}
	}
	if anyFlag(flagStripPLTReloc, flagStripPLTRelocLong) {
		if err := elfFile.StripSectionsByNames(elfrw.PLTRelocSectionsExact, false); err != nil {
			return fmt.Errorf("error removing PLT/relocation sections: %w", err)
		}
		if err := elfFile.StripSectionsByNames(elfrw.PLTRelocSectionsPrefix, true); err != nil {
			return fmt.Errorf("error removing PLT/relocation sections: %w", err)
		}
	}

	// Calculate the new file size
	newSize, err := elfFile.CalculateMemorySize()
	if err != nil {
		return fmt.Errorf("unable to calculate memory size: %w", err)
	}

	// If requested, truncate trailing zeros
	if *doZeroTrunc {
		newSize, err = elfFile.TruncateZeros(newSize)
		if err != nil {
			return fmt.Errorf("error truncating zeros: %w", err)
		}
		if newSize == 0 {
			return fmt.Errorf("the ELF file is completely empty")
		}
	}

	// Modify headers to reflect changes
	if err := elfFile.ModifyHeaders(newSize); err != nil {
		return fmt.Errorf("unable to modify headers: %w", err)
	}

	// Commit changes to the file
	if err := elfFile.CommitChanges(newSize); err != nil {
		return fmt.Errorf("unable to commit changes: %w", err)
	}

	return nil
}

func main() {
	flag.Parse()

	if len(os.Args) == 1 {
		printHelp()
		os.Exit(0)
	}

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	failures := 0
	for _, filename := range flag.Args() {
		if err := processFile(filename); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s: %s: %s\n", programName, filepath.Base(filename), err)
			failures++
		}
	}

	if failures > 0 {
		os.Exit(1)
	}
}
