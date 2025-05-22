package gosstrip

import (
	"debug/elf"
	"flag"
	"fmt"
	"io" // Added for io.EOF and io.SeekStart
	"os"
	"sstrip/elfrw"
)

var (
	doZeroTrunc = flag.Bool("z", false, "Also discard trailing zero bytes (alias for --zeroes).")
	doZeroes    = flag.Bool("zeroes", false, "Also discard trailing zero bytes.")
	showHelp    = flag.Bool("help", false, "Display this help and exit.")
	showVersion = flag.Bool("version", false, "Display version information and exit.")
)

const versionString = "Go sstrip, version 0.1 (based on sstrip 2.1)"

func customUsage() {
	_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] FILE...\n", os.Args[0])
	_, _ = fmt.Fprintln(os.Stderr, "Remove all nonessential bytes from executable ELF files.")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func processFile(filename string, zeroTrunc bool) error {
	file, err := os.OpenFile(filename, os.O_RDWR, 0) // 0 for perm means don't change if exists
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := elf.NewFile(file)
	if err != nil {
		return fmt.Errorf("not a valid ELF file: %w", err)
	}
	// elfFile.Close() is not needed here as elf.NewFile does not take ownership of the os.File for closing.

	ehdr, elfClass, elfData, err := elfrw.ReadEhdr(elfFile)
	if err != nil {
		return fmt.Errorf("failed to read ELF header: %w", err)
	}

	if elf.Type(ehdr.Type) != elf.ET_EXEC && elf.Type(ehdr.Type) != elf.ET_DYN {
		return fmt.Errorf("not an executable or shared-object library (type: %s)", elf.Type(ehdr.Type).String())
	}

	if ehdr.Phoff == 0 || ehdr.Phnum == 0 {
		return fmt.Errorf("ELF file has no program header table (Phoff: %d, Phnum: %d)", ehdr.Phoff, ehdr.Phnum)
	}

	phdrs, err := elfrw.ReadPhdrs(elfFile)
	if err != nil {
		return fmt.Errorf("failed to read program headers: %w", err)
	}

	if len(phdrs) == 0 { // ehdr.Phnum might be non-zero, but no headers parsed.
		return fmt.Errorf("ELF file has no program header table (phdrs slice empty despite Phnum=%d)", ehdr.Phnum)
	}

	fmt.Printf("Successfully read ELF info for %s:\n", filename)
	fmt.Printf("  Class: %s, Data: %s\n", elfClass, elfData)
	fmt.Printf("  ELF Header Type: %s, Machine: %s\n", elf.Type(ehdr.Type), elf.Machine(ehdr.Machine))
	fmt.Printf("  Num Program Headers: %d (from ehdr) / %d (read)\n", ehdr.Phnum, len(phdrs))

	newsize := ehdr.Phoff + (uint64(ehdr.Phnum) * uint64(ehdr.Phentsize))
	if newsize < uint64(ehdr.Ehsize) {
		newsize = uint64(ehdr.Ehsize)
	}

	for _, phdr := range phdrs {
		if elf.ProgType(phdr.Type) != elf.PT_NULL {
			segmentEnd := phdr.Off + phdr.Filesz
			if segmentEnd > newsize {
				newsize = segmentEnd
			}
		}
	}

	fmt.Printf("  Calculated initial newsize: %d (0x%x)\n", newsize, newsize)

	if zeroTrunc {
		readBuf := make([]byte, 1024)
		foundNonZero := false
	outerLoop:
		for {
			readN := int64(len(readBuf))
			if readN > int64(newsize) {
				readN = int64(newsize)
			}

			if readN == 0 {
				break // Nothing left to check
			}

			readOffset := int64(newsize) - readN
			n, errRead := file.ReadAt(readBuf[:readN], readOffset)

			if errRead != nil && errRead != io.EOF {
				return fmt.Errorf("failed to read for zero truncation: %w", errRead)
			}

			if n == 0 && readN > 0 && errRead != io.EOF {
				break
			}
			if n == 0 && errRead == io.EOF {
				break
			}

			for j := n - 1; j >= 0; j-- {
				if readBuf[j] != 0 {
					newsize = uint64(readOffset) + uint64(j) + 1
					foundNonZero = true
					break outerLoop
				}
			}

			newsize = uint64(readOffset)
			if newsize == 0 {
				break outerLoop
			}
			if n == 0 || errRead == io.EOF {
				break outerLoop
			}
		}
		_ = foundNonZero // To be used if we need to log if anything was truncated.

		if newsize == 0 {
			return fmt.Errorf("ELF file would be completely blank after zero truncation")
		}
		fmt.Printf("  After zero truncation, newsize: %d (0x%x)\n", newsize, newsize)
	}

	// Modify ELF Header (ehdr)
	if ehdr.Shoff >= newsize {
		fmt.Printf("  Section header table is being truncated (original shoff: %d).\n", ehdr.Shoff)
		ehdr.Shoff = 0
		ehdr.Shnum = 0
		ehdr.Shstrndx = 0
	}

	// Modify Program Headers (phdrs)
	fmt.Println("  Modifying program headers based on newsize:")
	for i, phdr := range phdrs {
		originalFilesz := phdr.Filesz // For logging
		originalOff := phdr.Off       // For logging

		if phdr.Off >= newsize {
			if originalFilesz > 0 { // Log only if it actually contained something
				fmt.Printf("    PHDR %d: Segment completely truncated (offset %d >= newsize %d). Filesz %d -> 0.\n", i, originalOff, newsize, originalFilesz)
			}
			phdr.Off = newsize // As per sstrip.c
			phdr.Filesz = 0
		} else if phdr.Off+phdr.Filesz > newsize {
			fmt.Printf("    PHDR %d: Segment partially truncated (offset %d + filesz %d > newsize %d). Filesz %d -> %d.\n", i, originalOff, originalFilesz, newsize, originalFilesz, newsize-phdr.Off)
			phdr.Filesz = newsize - phdr.Off
		}
	}

	// Commit Changes (commitchanges logic)
	fmt.Println("  Committing changes to file...")
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("could not rewind file: %w", err)
	}
	if err := elfrw.WriteEhdr(file, ehdr, elfClass, elfData); err != nil {
		return fmt.Errorf("could not write modified ELF header: %w", err)
	}

	if ehdr.Phoff == 0 && ehdr.Phnum > 0 {
		return fmt.Errorf("cannot write program headers: Phoff is 0 but Phnum is %d", ehdr.Phnum)
	}
	if ehdr.Phnum > 0 {
		if _, err := file.Seek(int64(ehdr.Phoff), io.SeekStart); err != nil {
			return fmt.Errorf("could not seek to program header table at offset %d: %w", ehdr.Phoff, err)
		}
		if err := elfrw.WritePhdrs(file, phdrs, elfClass, elfData); err != nil {
			return fmt.Errorf("could not write modified program headers: %w", err)
		}
	}

	programHeadersEnd := ehdr.Phoff + (uint64(ehdr.Phnum) * uint64(ehdr.Phentsize))
	if ehdr.Phnum == 0 {
		programHeadersEnd = uint64(ehdr.Ehsize)
		if ehdr.Phoff > programHeadersEnd {
			programHeadersEnd = ehdr.Phoff
		}
	}

	if newsize < programHeadersEnd {
		fmt.Printf("  Warning: newsize (%d) is less than end of program header table (%d). Adjusting newsize.\n", newsize, programHeadersEnd)
		newsize = programHeadersEnd
	}

	fmt.Printf("  Truncating file to newsize: %d (0x%x)\n", newsize, newsize)
	if err := file.Truncate(int64(newsize)); err != nil {
		return fmt.Errorf("could not truncate file: %w", err)
	}

	return nil
}

func main() {
	flag.Usage = customUsage
	flag.Parse()

	if *showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Println(versionString)
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(0)
	}

	actualDoZeroTrunc := *doZeroTrunc || *doZeroes
	failureCount := 0

	for _, filename := range flag.Args() {
		err := processFile(filename, actualDoZeroTrunc)
		if err != nil {
			progName := os.Args[0]
			_, _ = fmt.Fprintf(os.Stderr, "%s: %s: %v\n", progName, filename, err)
			failureCount++
		}
	}

	if failureCount > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}
