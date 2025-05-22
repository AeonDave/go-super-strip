package main

import (
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sstrip/elfrw"
	"sync"
)

// Configurazione del programma
type Config struct {
	ZeroTrunc   bool
	Verbose     bool
	Parallel    bool
	MaxWorkers  int
	ShowHelp    bool
	ShowVersion bool
}

// Statistiche di elaborazione
type ProcessStats struct {
	mu            sync.Mutex
	Processed     int
	Failed        int
	TotalReduced  int64
	OriginalSizes []int64
	NewSizes      []int64
}

const (
	versionString  = "Go sstrip, version 0.2 (optimized version based on sstrip 2.1)"
	readBufferSize = 8192 // Buffer più grande per migliori performance I/O
)

var (
	config = &Config{}
	stats  = &ProcessStats{}

	// Flag di comando
	doZeroTrunc = flag.Bool("z", false, "Also discard trailing zero bytes (alias for --zeroes)")
	doZeroes    = flag.Bool("zeroes", false, "Also discard trailing zero bytes")
	verbose     = flag.Bool("v", false, "Enable verbose output")
	parallel    = flag.Bool("j", false, "Process files in parallel")
	maxWorkers  = flag.Int("workers", 4, "Maximum number of parallel workers (default: 4)")
	showHelp    = flag.Bool("help", false, "Display this help and exit")
	showVersion = flag.Bool("version", false, "Display version information and exit")
)

// Errori personalizzati
var (
	ErrNotExecutable     = errors.New("not an executable or shared library")
	ErrNoProgramHeaders  = errors.New("no program header table found")
	ErrCompletelyBlank   = errors.New("file would be completely blank after processing")
	ErrInvalidFileFormat = errors.New("invalid ELF file format")
)

// ProcessResult rappresenta il risultato dell'elaborazione di un file
type ProcessResult struct {
	Filename     string
	OriginalSize int64
	NewSize      int64
	Error        error
}

func init() {
	flag.Usage = customUsage
}

func customUsage() {
	_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] FILE...\n", os.Args[0])
	_, _ = fmt.Fprintln(os.Stderr, "Remove all nonessential bytes from executable ELF files.")
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Examples:")
	_, _ = fmt.Fprintf(os.Stderr, "  %s -z /usr/bin/program     # Strip with zero truncation\n", os.Args[0])
	_, _ = fmt.Fprintf(os.Stderr, "  %s -j -workers=8 *.so     # Parallel processing with 8 workers\n", os.Args[0])
	_, _ = fmt.Fprintf(os.Stderr, "  %s -v file1 file2         # Verbose output\n", os.Args[0])
}

func parseFlags() {
	flag.Parse()

	config.ZeroTrunc = *doZeroTrunc || *doZeroes
	config.Verbose = *verbose
	config.Parallel = *parallel
	config.MaxWorkers = *maxWorkers
	config.ShowHelp = *showHelp
	config.ShowVersion = *showVersion

	// Validazione parametri
	if config.MaxWorkers < 1 {
		config.MaxWorkers = 1
	}
	if config.MaxWorkers > 16 {
		config.MaxWorkers = 16 // Limite ragionevole
	}
}

func processFile(filename string) *ProcessResult {
	result := &ProcessResult{Filename: filename}

	// Verifica esistenza e permessi del file
	fileInfo, err := os.Stat(filename)
	if err != nil {
		result.Error = fmt.Errorf("cannot access file: %w", err)
		return result
	}

	if !fileInfo.Mode().IsRegular() {
		result.Error = fmt.Errorf("not a regular file")
		return result
	}

	result.OriginalSize = fileInfo.Size()

	file, err := os.OpenFile(filename, os.O_RDWR, 0)
	if err != nil {
		result.Error = fmt.Errorf("failed to open file: %w", err)
		return result
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Elabora il file ELF
	newSize, err := processELFFile(file)
	if err != nil {
		result.Error = err
		return result
	}

	result.NewSize = newSize
	return result
}

func processELFFile(file *os.File) (int64, error) {
	// Parse ELF file
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidFileFormat, err)
	}

	// Legge le informazioni ELF
	elfInfo, err := elfrw.ReadELFInfo(elfFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read ELF info: %w", err)
	}

	ehdr := elfInfo.Header
	phdrs := elfInfo.Phdrs

	// Verifica che sia un file eseguibile o libreria condivisa
	if ehdr.Type != elf.ET_EXEC && ehdr.Type != elf.ET_DYN {
		return 0, fmt.Errorf("%w (type: %s)", ErrNotExecutable, ehdr.Type.String())
	}

	// Verifica presenza program headers
	if ehdr.Phoff == 0 || ehdr.Phnum == 0 || len(phdrs) == 0 {
		return 0, ErrNoProgramHeaders
	}

	if config.Verbose {
		logELFInfo(file.Name(), ehdr, len(phdrs))
	}

	// Calcola la nuova dimensione
	newSize := calculateNewSize(ehdr, phdrs)

	// Applica zero truncation se richiesta
	if config.ZeroTrunc {
		newSize, err = applyZeroTruncation(file, newSize)
		if err != nil {
			return 0, err
		}
	}

	// Modifica le strutture ELF
	modifyELFStructures(ehdr, phdrs, newSize)

	// Scrive le modifiche
	if err := commitChanges(file, ehdr, phdrs, newSize); err != nil {
		return 0, fmt.Errorf("failed to commit changes: %w", err)
	}

	return int64(newSize), nil
}

func calculateNewSize(ehdr *elfrw.Ehdr, phdrs []*elfrw.Phdr) uint64 {
	// Dimensione minima: header + program headers
	newSize := ehdr.Phoff + (uint64(ehdr.Phnum) * uint64(ehdr.Phentsize))
	if newSize < uint64(ehdr.Ehsize) {
		newSize = uint64(ehdr.Ehsize)
	}

	// Trova la fine dell'ultimo segmento non-NULL
	for _, phdr := range phdrs {
		if phdr.Type != elf.PT_NULL && phdr.Filesz > 0 {
			segmentEnd := phdr.Off + phdr.Filesz
			if segmentEnd > newSize {
				newSize = segmentEnd
			}
		}
	}

	return newSize
}

func applyZeroTruncation(file *os.File, currentSize uint64) (uint64, error) {
	if currentSize == 0 {
		return 0, ErrCompletelyBlank
	}

	readBuf := make([]byte, readBufferSize)
	newSize := currentSize

	// Legge dal fondo del file verso l'inizio
	for newSize > 0 {
		readSize := min(readBufferSize, int(newSize))
		offset := int64(newSize) - int64(readSize)

		n, err := file.ReadAt(readBuf[:readSize], offset)
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("failed to read for zero truncation: %w", err)
		}

		// Trova l'ultimo byte non-zero
		foundNonZero := false
		for i := n - 1; i >= 0; i-- {
			if readBuf[i] != 0 {
				newSize = uint64(offset) + uint64(i) + 1
				foundNonZero = true
				break
			}
		}

		if foundNonZero {
			break
		}

		newSize = uint64(offset)
	}

	if newSize == 0 {
		return 0, ErrCompletelyBlank
	}

	return newSize, nil
}

func modifyELFStructures(ehdr *elfrw.Ehdr, phdrs []*elfrw.Phdr, newSize uint64) {
	// Modifica ELF header se necessario
	if ehdr.Shoff >= newSize {
		if config.Verbose {
			fmt.Printf("  Section header table truncated (offset: %d)\n", ehdr.Shoff)
		}
		ehdr.Shoff = 0
		ehdr.Shnum = 0
		ehdr.Shstrndx = 0
	}

	// Modifica program headers
	for i, phdr := range phdrs {
		originalFilesz := phdr.Filesz

		if phdr.Off >= newSize {
			if originalFilesz > 0 && config.Verbose {
				fmt.Printf("  PHDR %d: Segment completely truncated\n", i)
			}
			phdr.Off = newSize
			phdr.Filesz = 0
		} else if phdr.Off+phdr.Filesz > newSize {
			if config.Verbose {
				fmt.Printf("  PHDR %d: Segment partially truncated (%d -> %d bytes)\n",
					i, originalFilesz, newSize-phdr.Off)
			}
			phdr.Filesz = newSize - phdr.Off
		}
	}
}

func commitChanges(file *os.File, ehdr *elfrw.Ehdr, phdrs []*elfrw.Phdr, newSize uint64) error {
	// Crea ELFInfo per la scrittura
	elfInfo := &elfrw.ELFInfo{
		Header: ehdr,
		Class:  ehdr.Class,
		Data:   ehdr.Data,
		Phdrs:  phdrs,
	}

	// Rewind e scrivi le strutture modificate
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("cannot rewind file: %w", err)
	}

	if err := elfrw.WriteELFInfo(file, elfInfo); err != nil {
		return fmt.Errorf("cannot write ELF structures: %w", err)
	}

	// Truncate il file alla nuova dimensione
	if err := file.Truncate(int64(newSize)); err != nil {
		return fmt.Errorf("cannot truncate file: %w", err)
	}

	return nil
}

func logELFInfo(filename string, ehdr *elfrw.Ehdr, phdrCount int) {
	fmt.Printf("Processing %s:\n", filepath.Base(filename))
	fmt.Printf("  Class: %s, Data: %s\n", ehdr.Class, ehdr.Data)
	fmt.Printf("  Type: %s, Machine: %s\n", ehdr.Type, ehdr.Machine)
	fmt.Printf("  Program Headers: %d\n", phdrCount)
}

func processFilesSequential(filenames []string) []ProcessResult {
	results := make([]ProcessResult, 0, len(filenames))

	for _, filename := range filenames {
		result := processFile(filename)
		results = append(results, *result)

		if config.Verbose {
			printResult(result)
		}
	}

	return results
}

func processFilesParallel(filenames []string) []ProcessResult {
	jobs := make(chan string, len(filenames))
	results := make(chan ProcessResult, len(filenames))

	// Avvia i worker
	var wg sync.WaitGroup
	for i := 0; i < config.MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filename := range jobs {
				result := processFile(filename)
				results <- *result
			}
		}()
	}

	// Invia i job
	go func() {
		for _, filename := range filenames {
			jobs <- filename
		}
		close(jobs)
	}()

	// Chiudi il canale dei risultati quando tutti i worker finiscono
	go func() {
		wg.Wait()
		close(results)
	}()

	// Raccogli i risultati
	var allResults []ProcessResult
	for result := range results {
		allResults = append(allResults, result)

		if config.Verbose {
			printResult(&result)
		}
	}

	return allResults
}

func printResult(result *ProcessResult) {
	if result.Error != nil {
		_, _ = fmt.Fprintf(os.Stderr, "  ❌ %s: %v\n", filepath.Base(result.Filename), result.Error)
	} else {
		reduction := result.OriginalSize - result.NewSize
		percentage := float64(reduction) / float64(result.OriginalSize) * 100
		fmt.Printf("  ✅ %s: %d -> %d bytes (%.1f%% reduction)\n",
			filepath.Base(result.Filename), result.OriginalSize, result.NewSize, percentage)
	}
}

func updateStats(results []ProcessResult) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	for _, result := range results {
		stats.Processed++
		if result.Error != nil {
			stats.Failed++
		} else {
			reduction := result.OriginalSize - result.NewSize
			stats.TotalReduced += reduction
			stats.OriginalSizes = append(stats.OriginalSizes, result.OriginalSize)
			stats.NewSizes = append(stats.NewSizes, result.NewSize)
		}
	}
}

func printSummary() {
	if stats.Processed == 0 {
		return
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Files processed: %d\n", stats.Processed)
	fmt.Printf("  Successful: %d\n", stats.Processed-stats.Failed)
	fmt.Printf("  Failed: %d\n", stats.Failed)

	if stats.TotalReduced > 0 {
		fmt.Printf("  Total space saved: %d bytes\n", stats.TotalReduced)

		if len(stats.OriginalSizes) > 0 {
			var totalOriginal, totalNew int64
			for i, original := range stats.OriginalSizes {
				totalOriginal += original
				totalNew += stats.NewSizes[i]
			}

			if totalOriginal > 0 {
				percentage := float64(stats.TotalReduced) / float64(totalOriginal) * 100
				fmt.Printf("  Average reduction: %.1f%%\n", percentage)
			}
		}
	}
}

func main() {
	parseFlags()

	if config.ShowHelp {
		flag.Usage()
		os.Exit(0)
	}

	if config.ShowVersion {
		fmt.Println(versionString)
		os.Exit(0)
	}

	filenames := flag.Args()
	if len(filenames) == 0 {
		flag.Usage()
		os.Exit(0)
	}

	// Elabora i file
	var results []ProcessResult
	if config.Parallel && len(filenames) > 1 {
		if config.Verbose {
			fmt.Printf("Processing %d files with %d workers...\n", len(filenames), config.MaxWorkers)
		}
		results = processFilesParallel(filenames)
	} else {
		results = processFilesSequential(filenames)
	}

	// Aggiorna le statistiche
	updateStats(results)

	// Stampa errori non verbose
	if !config.Verbose {
		for _, result := range results {
			if result.Error != nil {
				_, _ = fmt.Fprintf(os.Stderr, "%s: %s: %v\n", os.Args[0], result.Filename, result.Error)
			}
		}
	}

	// Stampa sommario se più di un file o se verbose
	if len(filenames) > 1 || config.Verbose {
		printSummary()
	}

	// Exit con codice appropriato
	if stats.Failed > 0 {
		os.Exit(1)
	}
}
