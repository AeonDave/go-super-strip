package main

import (
	"flag"
	"fmt"
	elfrw "gosstrip/elfrw"
	perw "gosstrip/perw"
	"os"
	"regexp"
)

var (
	filePath = flag.String("file", "", "Path to executable file")
	// strip single-letter flags
	stripA     = flag.Bool("a", false, "strip section table/dynamic data")
	stripB     = flag.Bool("b", false, "strip debug sections")
	stripC     = flag.Bool("c", false, "strip symbol sections")
	stripD     = flag.Bool("d", false, "strip string sections")
	stripAll   = flag.Bool("A", false, "strip all metadata")
	stripRegex = flag.String("s", "", "strip bytes matching regex pattern")
	// obfuscate all
	obfAll = flag.Bool("O", false, "apply all obfuscation")
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
	// strip options
	if *stripAll || *stripA || *stripB || *stripC || *stripD {
		opts := map[string]bool{"all": *stripAll}
		if *stripA {
			opts["sectionTable"] = true
		}
		if *stripB {
			opts["debug"] = true
		}
		if *stripC {
			opts["symbols"] = true
		}
		if *stripD {
			opts["strings"] = true
		}
		handler.Strip(opts)
		acted = true
	}
	// obfuscate all
	if *obfAll {
		handler.Obfuscate(map[string]bool{"all": true})
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
	fmt.Println(`Usage:
  -file <path>            Path to executable file
  -s <pattern>            Strip bytes matching regex pattern
  -a                       Strip section table/dynamic data
  -b                       Strip debug sections
  -c                       Strip symbol sections
  -d                       Strip string sections
  -A                       Strip all metadata
  -O                       Apply all obfuscation
Examples:
  main -file a.out -a -b -s debug
  main -file a.out -A
  main -file a.exe -O`)
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
		checkErr(h.e.StripAllMetadata())
	} else {
		if opts["debug"] {
			checkErr(h.e.StripSectionsByNames(elfrw.DebugSectionsExact, false))
			checkErr(h.e.StripSectionsByNames(elfrw.DebugSectionsPrefix, true))
		}
		if opts["symbols"] {
			checkErr(h.e.StripSectionsByNames(elfrw.SymbolsSectionsExact, false))
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
	matches := h.e.StripByteRegex(re)
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
		checkErr(h.p.StripAllMetadata())
	} else {
		if opts["debug"] {
			checkErr(h.p.StripSectionsByNames(perw.DebugSectionsExact, false))
		}
		if opts["symbols"] {
			checkErr(h.p.StripSectionsByNames(perw.SymbolSectionsExact, false))
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
	matches := h.p.StripByteRegex(re)
	fmt.Printf("PE: stripped %d matches\n", matches)
}
