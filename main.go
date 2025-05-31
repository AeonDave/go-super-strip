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

	// Stripping options
	stripDebug   = flag.Bool("strip-debug", false, "Strip debug sections")
	stripSymbols = flag.Bool("strip-symbols", false, "Strip symbol sections")
	stripAllMeta = flag.Bool("strip-all", false, "Strip all non-essential metadata (includes debug, symbols)")

	// Obfuscation options
	obfSecNames = flag.Bool("obf-names", false, "Obfuscate by randomizing section names")
	obfBaseAddr = flag.Bool("obf-base", false, "Obfuscate base addresses")
	obfAll      = flag.Bool("obf-all", false, "Apply all available obfuscations")
)

func main() {
	flag.Parse()
	if *filePath == "" {
		printUsage()
		return
	}

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

	// Stripping options
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
	if actedOnStrip {
		handler.Strip(stripOpts)
		acted = true
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
	}
	if actedOnObfuscate {
		handler.Obfuscate(obfOpts)
		acted = true
	}

	if acted {
		handler.Commit()
	} else {
		printUsage()
	}
}

type FileHandler interface {
	PrintInfo()
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
		handler := &PEHandler{pe}
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
  -strip-debug            Strip debug sections from the file.
  -strip-symbols          Strip symbol table sections.
  -strip-all              Strip all non-essential metadata (recommended for maximum size reduction; includes debug and symbols).

Obfuscation Options:
  -obf-names              Randomize section names to hinder analysis.
  -obf-base               Obfuscate base addresses (if applicable to format).
  -obf-all                Apply all available obfuscation techniques (includes name randomization and base address obfuscation).

Examples:
  go-super-strip -file a.out -strip-all
  go-super-strip -file myapp.exe -strip-debug -strip-symbols -s "ConfidentialBuild"
  go-super-strip -file service.elf -obf-all
  go-super-strip -file lib.dll -obf-names -obf-base`)
}

// --- ELF Handler ---

type ELFHandler struct{ e *elfrw.ELFFile }

func (h *ELFHandler) PrintInfo() {
	fmt.Println("Format: ELF")
	fmt.Printf("File: %s\n", h.e.FileName)
	fmt.Printf("Sections:\n")
	for _, s := range h.e.Sections {
		fmt.Printf("  %s (offset: 0x%x, size: 0x%x)\n", s.Name, s.Offset, s.Size)
	}
	fmt.Printf("Segments:\n")
	for _, seg := range h.e.Segments {
		fmt.Printf("  Type: %d, Offset: 0x%x, Size: 0x%x\n", seg.Type, seg.Offset, seg.Size)
	}
}

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
	matches := h.e.StripByteRegex(re, false)
	fmt.Printf("ELF: stripped %d matches\n", matches)
}

// --- PE Handler ---

type PEHandler struct{ p *perw.PEFile }

func (h *PEHandler) PrintInfo() {
	fmt.Println("Format: PE")
	fmt.Printf("File: %s\n", h.p.FileName)
	fmt.Printf("Sections:\n")
	for _, s := range h.p.Sections {
		fmt.Printf("  %s (offset: 0x%x, size: 0x%x)\n", s.Name, s.Offset, s.Size)
	}
}

func (h *PEHandler) Strip(opts map[string]bool) {
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
	if opts["all"] {
		checkErr(h.p.ObfuscateAll())
	} else {
		if opts["names"] {
			checkErr(h.p.RandomizeSectionNames())
		}
		if opts["base"] {
			checkErr(h.p.ObfuscateBaseAddresses())
		}
	}
}

func (h *PEHandler) Commit() {
	size, err := h.p.CalculatePhysicalFileSize()
	checkErr(err)
	size, err = h.p.TruncateZeros(size)
	checkErr(err)
	checkErr(h.p.CommitChanges(int64(size)))
}

// StripRegex overwrites byte patterns matching a regex in all sections
func (h *PEHandler) StripRegex(pat string) {
	re := regexp.MustCompile(pat)
	matches := h.p.StripByteRegex(re, false)
	fmt.Printf("PE: stripped %d matches\n", matches)
}
