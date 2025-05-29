package main

import (
	"flag"
	"fmt"
	elfrw "gosstrip/elfrw"
	"gosstrip/perw"
	"os"
	"strings"
)

type Command string

const (
	CmdInfo      Command = "info"
	CmdStrip     Command = "strip"
	CmdObfuscate Command = "obfuscate"
)

var (
	cmd        = flag.String("cmd", "info", "Command: info, strip, obfuscate")
	filePath   = flag.String("file", "", "Path to executable file")
	stripFlags = flag.String("strip", "", "Strip options (comma-separated: debug,symbols,all)")
	obfFlags   = flag.String("obf", "", "Obfuscation options (comma-separated: names,base,all)")
	showHelp   = flag.Bool("h", false, "Show help")
)

func main() {
	flag.Parse()
	if *showHelp || *filePath == "" {
		printUsage()
		return
	}

	f, err := os.OpenFile(*filePath, os.O_RDWR, 0)
	checkErr(err)
	defer f.Close()

	_, handler, err := detectFormat(f)
	checkErr(err)

	switch Command(*cmd) {
	case CmdInfo:
		handler.PrintInfo()
	case CmdStrip:
		handler.Strip(parseOptions(*stripFlags))
		handler.Commit()
	case CmdObfuscate:
		handler.Obfuscate(parseOptions(*obfFlags))
		handler.Commit()
	default:
		fmt.Println("Unknown command")
		printUsage()
	}
}

// --- Utility types and functions ---

type FileHandler interface {
	PrintInfo()
	Strip(opts map[string]bool)
	Obfuscate(opts map[string]bool)
	Commit()
}

func detectFormat(f *os.File) (string, FileHandler, error) {
	buf := make([]byte, 5)
	_, err := f.ReadAt(buf, 0)
	if err != nil {
		return "", nil, err
	}
	f.Seek(0, 0)
	switch {
	case buf[0] == 0x7f && string(buf[1:4]) == "ELF":
		elf, err := elfrw.ReadELF(f)
		if err != nil {
			return "ELF", nil, err
		}
		return "ELF", &ELFHandler{elf}, nil
	case buf[0] == 'M' && buf[1] == 'Z':
		pe, err := perw.ReadPE(f)
		if err != nil {
			return "PE", nil, err
		}
		return "PE", &PEHandler{pe}, nil
	default:
		return "", nil, fmt.Errorf("unknown file format")
	}
}

func parseOptions(opt string) map[string]bool {
	opts := map[string]bool{}
	for _, o := range strings.Split(opt, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			opts[o] = true
		}
	}
	return opts
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage:
  -file <path>      Path to executable
  -cmd <command>    info | strip | obfuscate
  -strip <opts>     Strip options: debug,symbols,all
  -obf <opts>       Obfuscate options: names,base,all
Examples:
  main -file a.out -cmd info
  main -file a.out -cmd strip -strip all
  main -file a.exe -cmd obfuscate -obf names,base
`)
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
