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

	// Options for stripping techniques
	stripSections = flag.Bool("s", false, "Remove the section table")
	stripDebug    = flag.Bool("d", false, "Remove debug information")
	stripSymbols  = flag.Bool("y", false, "Remove symbol tables")
	stripNonLoad  = flag.Bool("n", false, "Remove non-loadable segments")
	stripStrings  = flag.Bool("t", false, "Remove string tables")
	randomNames   = flag.Bool("r", false, "Randomize section names")
	stripAll      = flag.Bool("A", false, "Apply all stripping techniques")
)

// Alternative version for --zeroes
func init() {
	flag.BoolVar(doZeroTrunc, "zeroes", false, "Also remove trailing zero bytes")
}

func printHelp() {
	fmt.Printf("Usage: %s [OPTIONS] FILE...\n", programName)
	fmt.Println("Removes all non-essential bytes from ELF executable files.")
	fmt.Println("  -z, --zeroes        Also remove trailing zero bytes.")
	fmt.Println("  -s                  Remove the section table.")
	fmt.Println("  -d                  Remove debug information.")
	fmt.Println("  -y                  Remove symbol tables.")
	fmt.Println("  -n                  Remove non-loadable segments.")
	fmt.Println("  -t                  Remove string tables.")
	fmt.Println("  -r                  Randomize section names.")
	fmt.Println("  -A                  Apply all stripping techniques.")
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

func processFile(filename string) error {
	// Open the file in read/write mode
	file, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Read the ELF header
	elfFile, err := elfrw.ReadELF(file)
	if err != nil {
		return fmt.Errorf("not a valid ELF file: %w", err)
	}

	// Check that it is an executable or shared library
	if !elfFile.IsExecutableOrShared() {
		return fmt.Errorf("not an executable or shared library")
	}

	// Apply the selected stripping techniques
	if *stripAll || *stripSections {
		err = elfFile.StripSections()
		if err != nil {
			return fmt.Errorf("error removing section table: %w", err)
		}
	}

	if *stripAll || *stripDebug {
		err = elfFile.StripDebugInfo()
		if err != nil {
			return fmt.Errorf("error removing debug information: %w", err)
		}
	}

	if *stripAll || *stripSymbols {
		err = elfFile.StripSymbols()
		if err != nil {
			return fmt.Errorf("error removing symbol tables: %w", err)
		}
	}

	if *stripAll || *stripNonLoad {
		err = elfFile.StripNonLoadable()
		if err != nil {
			return fmt.Errorf("error removing non-loadable segments: %w", err)
		}
	}

	if *stripAll || *stripStrings {
		err = elfFile.StripStrings()
		if err != nil {
			return fmt.Errorf("error removing string tables: %w", err)
		}
	}

	if *stripAll || *randomNames {
		err = elfFile.RandomizeSectionNames()
		if err != nil {
			return fmt.Errorf("error renaming sections: %w", err)
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

		// Sanity check
		if newSize == 0 {
			return fmt.Errorf("the ELF file is completely empty")
		}
	}

	// Modify headers to reflect changes
	err = elfFile.ModifyHeaders(newSize)
	if err != nil {
		return fmt.Errorf("unable to modify headers: %w", err)
	}

	// Commit changes to the file
	err = elfFile.CommitChanges(newSize)
	if err != nil {
		return fmt.Errorf("unable to commit changes: %w", err)
	}

	return nil
}

func main() {
	// Parse command-line flags
	flag.Parse()

	// If there are no arguments, show help
	if len(os.Args) == 1 {
		printHelp()
		os.Exit(0)
	}

	// Handle help and version flags
	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	// Process each specified file
	failures := 0
	for _, filename := range flag.Args() {
		err := processFile(filename)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s: %s: %s\n", programName, filepath.Base(filename), err)
			failures++
		}
	}

	// Exit with an error code if there were failures
	if failures > 0 {
		os.Exit(1)
	}
}
