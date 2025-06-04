package main

import (
	"flag"
	"fmt"
	"gosstrip/elfrw"
	"gosstrip/perw"
	"os"
	"regexp"
)

var (
	filePath = flag.String("file", "", "Path to executable file")

	// Regex stripping
	stripRegex = flag.String("s", "", "Strip bytes matching regex pattern (e.g., \"UPX!\")")

	// Stripping options - both short and long forms point to same variable
	stripDebug   *bool
	stripSymbols *bool
	stripAllMeta *bool

	// Obfuscation options - both short and long forms point to same variable
	obfSecNames    *bool
	obfBaseAddr    *bool
	obfLoadConfig  *bool
	obfImportTable *bool
	obfImports     *bool
	obfAll         *bool
)

func init() {
	// Initialize flags with both short and long forms pointing to same variables
	stripDebug = flag.Bool("strip-debug", false, "Strip debug sections")
	flag.BoolVar(stripDebug, "d", false, "Strip debug sections")

	stripSymbols = flag.Bool("strip-symbols", false, "Strip symbol sections")
	flag.BoolVar(stripSymbols, "y", false, "Strip symbol sections")

	stripAllMeta = flag.Bool("strip-all", false, "Strip all non-essential metadata (includes debug, symbols)")
	flag.BoolVar(stripAllMeta, "S", false, "Strip all non-essential metadata")

	obfSecNames = flag.Bool("obf-names", false, "Obfuscate by randomizing section names")
	flag.BoolVar(obfSecNames, "n", false, "Obfuscate by randomizing section names")

	obfBaseAddr = flag.Bool("obf-base", false, "Obfuscate base addresses")
	flag.BoolVar(obfBaseAddr, "b", false, "Obfuscate base addresses")

	obfLoadConfig = flag.Bool("obf-load-config", false, "Obfuscate load configuration directory")
	flag.BoolVar(obfLoadConfig, "l", false, "Obfuscate load configuration directory")

	obfImportTable = flag.Bool("obf-import-table", false, "Obfuscate import table metadata (PE files only)")
	flag.BoolVar(obfImportTable, "i", false, "Obfuscate import table metadata (PE files only)")

	obfImports = flag.Bool("obf-imports", false, "Obfuscate import table entries by randomizing names (PE files only)")
	flag.BoolVar(obfImports, "m", false, "Obfuscate import table entries by randomizing names (PE files only)")

	obfAll = flag.Bool("obf-all", false, "Apply all available obfuscations")
	flag.BoolVar(obfAll, "O", false, "Apply all available obfuscations")
}

func main() {
	flag.Parse()
	if *filePath == "" {
		printUsage()
		return
	}
	// Collect all the operations that would be performed
	stripOpts := make(map[string]bool)
	actedOnStrip := false
	if *stripAllMeta {
		stripOpts["all"] = true
		actedOnStrip = true
	} else {
		if *stripDebug {
			stripOpts["debug"] = true
			actedOnStrip = true
		}
		if *stripSymbols {
			stripOpts["symbols"] = true
			actedOnStrip = true
		}
	}
	// Obfuscation options
	obfOpts := make(map[string]bool)
	actedOnObfuscate := false
	if *obfAll {
		obfOpts["all"] = true
		actedOnObfuscate = true
	} else {
		if *obfSecNames {
			obfOpts["names"] = true
			actedOnObfuscate = true
		}
		if *obfBaseAddr {
			obfOpts["base"] = true
			actedOnObfuscate = true
		}
		if *obfLoadConfig {
			obfOpts["loadconfig"] = true
			actedOnObfuscate = true
		}
		if *obfImportTable {
			obfOpts["importtable"] = true
			actedOnObfuscate = true
		}
		if *obfImports {
			obfOpts["imports"] = true
			actedOnObfuscate = true
		}
	}

	// Special handling for UPX signature removal before full PE parsing
	if *stripRegex == "UPX!" {
		fmt.Println("Detected UPX signature removal request - using raw file method")
		matches, err := perw.StripUPXSignatureFromRawPE(*filePath)
		if err != nil {
			fmt.Printf("UPX signature removal failed: %v\n", err)
			checkErr(err)
		} else {
			fmt.Printf("Successfully removed %d UPX signature(s)\n", matches)
			return
		}
	}

	// Open file with read-write permissions
	f, err := os.OpenFile(*filePath, os.O_RDWR, 0)
	checkErr(err)
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	_, handler, err := detectFormat(f)
	checkErr(err)

	// dispatch based on flags
	acted := false
	// strip by regex
	if *stripRegex != "" {
		handler.StripRegex(*stripRegex)
		acted = true
	}

	if actedOnStrip {
		handler.Strip(stripOpts)
		acted = true
	}
	if actedOnObfuscate {
		handler.Obfuscate(obfOpts)
		acted = true
	}
	if acted {
		// For PE files, use different commit strategies based on operations performed
		if peHandler, ok := handler.(*PEHandler); ok {
			if actedOnObfuscate && peHandler.needsHeaderUpdates {
				// Some obfuscation operations need full header updates
				peHandler.CommitWithHeaders()
			} else {
				// Stripping and some obfuscation operations use simple commit
				handler.Commit()
			}
		} else {
			// For ELF files, use normal commit
			handler.Commit()
		}
	} else {
		printUsage()
	}
}

type FileHandler interface {
	Strip(opts map[string]bool)
	StripRegex(pattern string)
	Obfuscate(opts map[string]bool)
	Commit()
}

func detectFormat(f *os.File) (string, FileHandler, error) {
	buf := make([]byte, 5)
	_, err := f.ReadAt(buf, 0)
	if err != nil {
		return "", nil, err
	}
	_, _ = f.Seek(0, 0)
	switch {
	case buf[0] == 0x7f && string(buf[1:4]) == "ELF":
		elf, err := elfrw.ReadELF(f)
		if err != nil {
			return "ELF", nil, err
		}
		handler := &ELFHandler{elf}
		return "ELF", handler, nil
	case buf[0] == 'M' && buf[1] == 'Z':
		pe, err := perw.ReadPE(f)
		if err != nil {
			return "PE", nil, err
		}
		handler := &PEHandler{p: pe, needsHeaderUpdates: false, wasStripped: false}
		return "PE", handler, nil
	default:
		return "", nil, fmt.Errorf("unknown file format")
	}
}

func checkErr(err error) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: go-super-strip -file <path> [options]

Path to executable file:
  -file <path>            Specify the path to the executable file.

Generic Stripping:
  -s <pattern>            Strip bytes matching a regex pattern (e.g., -s "UPX!" to remove UPX signatures).

Metadata Stripping Options:
  -strip-debug, -d        Strip debug sections from the file.
  -strip-symbols, -y      Strip symbol table sections.
  -strip-all, -S          Strip all non-essential metadata (recommended for maximum size reduction; includes debug and symbols).

Obfuscation Options:
  -obf-names, -n          Randomize section names to hinder analysis.
  -obf-base, -b           Obfuscate base addresses (if applicable to format).
  -obf-load-config, -l    Obfuscate load configuration directory (PE files only).
  -obf-import-table, -i   Obfuscate import table metadata (PE files only).
  -obf-imports, -m        Obfuscate import table entries by randomizing names (PE files only).
  -obf-all, -O            Apply all available obfuscation techniques.

Examples:
  # Basic operations:
  go-super-strip -file a.out -S                    # Strip all metadata (short form)
  go-super-strip -file a.out -strip-all            # Strip all metadata (long form)
  go-super-strip -file myapp.exe -d -y -s "Build"  # Strip debug, symbols, and custom pattern
    # Obfuscation operations:
  go-super-strip -file service.elf -O              # Apply all obfuscations (short form)
  go-super-strip -file lib.dll -n -b               # Randomize names and obfuscate base (short form)  go-super-strip -file app.exe -l                  # Obfuscate load config only (short form)
  go-super-strip -file app.exe -i                  # Obfuscate import table only (short form)
  go-super-strip -file app.exe -obf-import-table   # Obfuscate import table only (long form)
  go-super-strip -file app.exe -obf-imports        # Aggressive import name obfuscation (long form)
  go-super-strip -file binary -S -O                # Strip everything and obfuscate everything

⚠️  WARNING: Some operations can break executables. See README.md for risk analysis.`)
}

// --- ELF Handler ---

type ELFHandler struct{ e *elfrw.ELFFile }

func (h *ELFHandler) Strip(opts map[string]bool) {
	if opts["all"] {
		checkErr(h.e.StripAllMetadata(false))
	} else {
		if opts["debug"] {
			checkErr(h.e.StripDebugSections(false))
		}
		if opts["symbols"] {
			checkErr(h.e.StripSymbolTables(false))
		}
	}
}

func (h *ELFHandler) Obfuscate(opts map[string]bool) {
	if opts["all"] {
		checkErr(h.e.ObfuscateAll())
	} else {
		if opts["names"] {
			checkErr(h.e.RandomizeSectionNames())
		}
		if opts["base"] {
			checkErr(h.e.ObfuscateBaseAddresses())
		}
	}
}

func (h *ELFHandler) Commit() {
	size, err := h.e.CalculateMemorySize()
	checkErr(err)
	size, err = h.e.TruncateZeros(size)
	checkErr(err)
	checkErr(h.e.CommitChanges(size))
}

// StripRegex overwrites byte patterns matching a regex in all sections
func (h *ELFHandler) StripRegex(pat string) {
	re := regexp.MustCompile(pat)
	fmt.Printf("ELF: attempting to strip pattern '%s'\n", pat)
	matches, err := h.e.StripByteRegex(re, false)
	checkErr(err)
	fmt.Printf("ELF: stripped %d matches\n", matches)
}

// --- PE Handler ---

type PEHandler struct {
	p                  *perw.PEFile
	needsHeaderUpdates bool
	wasStripped        bool
}

func (h *PEHandler) Strip(opts map[string]bool) {
	h.wasStripped = true // Mark that stripping operations were performed

	if opts["all"] {
		checkErr(h.p.StripAllMetadata(false))
	} else {
		if opts["debug"] {
			checkErr(h.p.StripDebugSections(false))
		}
		if opts["symbols"] {
			checkErr(h.p.StripSymbolTables(false))
		}
	}
}

func (h *PEHandler) Obfuscate(opts map[string]bool) {
	var needsHeaderUpdates bool

	if opts["all"] {
		checkErr(h.p.ObfuscateAll())
		needsHeaderUpdates = false // For now, don't use header updates for any obfuscation	} else {
		if opts["names"] {
			checkErr(h.p.RandomizeSectionNames())
			// Section name randomization modifies headers directly, doesn't need header updates
		}
		if opts["base"] {
			checkErr(h.p.ObfuscateBaseAddresses())
			needsHeaderUpdates = false // Base address obfuscation also modifies raw data directly
		}
		if opts["loadconfig"] {
			checkErr(h.p.ObfuscateLoadConfig())
			needsHeaderUpdates = false // Load config obfuscation modifies raw data directly
		}
		if opts["importtable"] {
			checkErr(h.p.ObfuscateImportTable())
			needsHeaderUpdates = false // Import table obfuscation modifies raw data directly
		}
		if opts["imports"] {
			checkErr(h.p.ObfuscateImportNames())
			needsHeaderUpdates = false // Import name obfuscation modifies raw data directly
		}
	}

	// Store whether this obfuscation needs header updates
	h.needsHeaderUpdates = needsHeaderUpdates
}

func (h *PEHandler) Commit() {
	// For obfuscation-only operations, preserve original file size
	// For stripping operations, use calculated physical size
	var size int64

	if h.wasStripped {
		// If stripping was performed, calculate the reduced size
		calculatedSize, err := h.p.CalculatePhysicalFileSize()
		checkErr(err)
		size = int64(calculatedSize)
	} else {
		// If only obfuscation was performed, preserve original size
		// Pass 0 to CommitChangesSimple to use full RawData length
		size = 0
	}

	// Use simple commit to avoid header corruption issues
	checkErr(h.p.CommitChangesSimple(size))
}

func (h *PEHandler) CommitWithHeaders() {
	size, err := h.p.CalculatePhysicalFileSize()
	checkErr(err)
	// Full commit with header updates for obfuscation operations
	checkErr(h.p.CommitChanges(int64(size)))
}

func (h *PEHandler) StripRegex(pat string) {
	h.wasStripped = true // Mark that stripping operations were performed

	fmt.Printf("PE: attempting to strip pattern '%s'\n", pat)

	// Special handling for UPX signatures on potentially packed files
	if pat == "UPX!" {
		fmt.Println("PE: Detected UPX signature pattern, using raw file method for packed PE compatibility")
		matches, err := perw.StripUPXSignatureFromRawPE(h.p.FileName)
		if err != nil {
			fmt.Printf("PE: Raw UPX signature stripping failed, trying standard method: %v\n", err)
			// Fallback to standard method
			re := regexp.MustCompile(pat)
			matches, err = h.p.StripBytePattern(re, perw.ZeroFill)
			checkErr(err)
		}
		fmt.Printf("PE: stripped %d UPX signature matches\n", matches)
		return
	}

	// Standard regex stripping for other patterns
	re := regexp.MustCompile(pat)
	matches, err := h.p.StripBytePattern(re, perw.ZeroFill)
	checkErr(err)
	fmt.Printf("PE: stripped %d matches\n", matches)
}
