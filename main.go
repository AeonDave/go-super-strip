package main

import (
	"flag"
	"fmt"
	"gosstrip/common"
	"gosstrip/elfrw"
	"gosstrip/pack"
	"gosstrip/perw"
	"os"
	"regexp"
	"strings"
	"unicode"
)

const defaultPackOptions = "compression=lzma,level=9,encryption=chacha20"

type Configuration struct {
	FilePath       string
	Verbose        bool
	Analyze        bool   // -a: Analyze file structure only (standalone)
	Strip          bool   // -s: Strip info, metadata and sections
	Obfuscate      bool   // -o: Apply obfuscation techniques
	Compact        bool   // -c: Apply file size reduction
	Insert         string // -i: Add section (format: name:filepath[:password])
	Overlay        string // -l: Add overlay (format: filepath[:password])
	Regex          string // -r: Strip bytes matching regex pattern
	Pack           string // -p: Pack with compression and polymorphic stub (format: opt1=val1,opt2=val2)
	StripForce     bool   // -s=force: risky strip operations for -s
	CompactForce   bool   // -c=force: enable risky compaction operations
	ObfuscateForce bool   // -o=force: risky obfuscation operations for -o
}

var (
	analyzeFlag     = flag.Bool("a", false, "Analyze executable file structure and exit")
	analyzeFlagLong = flag.Bool("analyze", false, "Analyze executable file structure and exit")

	stripFlag     = flag.Bool("s", false, "StripAll debug and symbol sections")
	stripFlagLong = flag.Bool("strip", false, "StripAll debug and symbol sections")

	obfuscateFlag     = flag.Bool("o", false, "Apply obfuscation techniques")
	obfuscateFlagLong = flag.Bool("obfuscate", false, "Apply obfuscation techniques")

	compactFlag     = flag.Bool("c", false, "Apply file size reduction by removing sections")
	compactFlagLong = flag.Bool("compact", false, "Apply file size reduction by removing sections")

	insertFlag     = flag.String("i", "", "Add hex section (format: name:data_or_file[:password])")
	insertFlagLong = flag.String("insert", "", "Add hex section (format: name:data_or_file[:password])")

	overlayFlag     = flag.String("l", "", "Add overlay (format: data_or_file[:password])")
	overlayFlagLong = flag.String("overlay", "", "Add overlay (format: data_or_file[:password])")

	regexFlag     = flag.String("r", "", "StripAll bytes matching regex pattern")
	regexFlagLong = flag.String("regex", "", "StripAll bytes matching regex pattern")

	packFlag     = flag.String("p", "", "Pack executable with compression and polymorphic stub (format: opt1=val1,opt2=val2)")
	packFlagLong = flag.String("pack", "", "Pack executable with compression and polymorphic stub (format: opt1=val1,opt2=val2)")

	// Other
	verboseFlag = flag.Bool("v", false, "Enable verbose output")
	helpFlag    = flag.Bool("h", false, "Show this help")
)

func main() {
	for _, arg := range os.Args {
		if arg == "-h" || arg == "--help" {
			printUsage()
			return
		}
	}

	// Preprocess -s/-o suboptions and -p defaults before parsing flags
	preprocessOperationFlags()
	// Preprocess -p/--pack flags with no value so they won't consume the file path
	preprocessPackFlags()

	config, err := parseArgs()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		printUsage()
		os.Exit(1)
	}
	if config.Verbose {
		// TODO: Implement debug logging
	}
	if err := runOperations(config); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

var preStripForce bool
var preObfForce bool
var preCompactForce bool

func preprocessOperationFlags() {
	if len(os.Args) == 0 {
		return
	}
	normalizeBool := func(v string) (bool, bool) {
		v = strings.TrimSpace(strings.ToLower(v))
		switch v {
		case "", "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off":
			return true, false
		default:
			return false, false
		}
	}
	parseForce := func(optStr string) (found bool, val bool) {
		parts := strings.Split(optStr, ",")
		for _, p := range parts {
			kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			if key == "force" || key == "f" {
				if len(kv) == 1 {
					return true, true
				}
				ok, b := normalizeBool(kv[1])
				if ok {
					return true, b
				}
			}
		}
		return false, false
	}

	args := os.Args[:0]
	for _, a := range os.Args {
		if strings.HasPrefix(a, "-s=") || strings.HasPrefix(a, "--strip=") {
			opt := a[strings.Index(a, "=")+1:]
			if found, v := parseForce(opt); found {
				preStripForce = v
			}
			args = append(args, "-s")
			continue
		}
		if strings.HasPrefix(a, "-o=") || strings.HasPrefix(a, "--obfuscate=") {
			opt := a[strings.Index(a, "=")+1:]
			if found, v := parseForce(opt); found {
				preObfForce = v
			}
			args = append(args, "-o")
			continue
		}
		if strings.HasPrefix(a, "-c=") || strings.HasPrefix(a, "--compact=") {
			opt := a[strings.Index(a, "=")+1:]
			if found, v := parseForce(opt); found {
				preCompactForce = v
			}
			args = append(args, "-c")
			continue
		}
		args = append(args, a)
	}
	os.Args = args
}

func preprocessPackFlags() {
	if len(os.Args) == 0 {
		return
	}
	args := os.Args[:0]
	for _, a := range os.Args {
		switch a {
		case "-p":
			args = append(args, "-p="+defaultPackOptions)
			continue
		case "--pack":
			args = append(args, "--pack="+defaultPackOptions)
			continue
		case "-p=":
			args = append(args, "-p="+defaultPackOptions)
			continue
		case "--pack=":
			args = append(args, "--pack="+defaultPackOptions)
			continue
		}
		args = append(args, a)
	}
	os.Args = args
}

func parseArgs() (*Configuration, error) {
	flag.Parse()
	if *helpFlag {
		printUsage()
		os.Exit(0)
	}
	args := flag.Args()
	if len(args) != 1 {
		return nil, fmt.Errorf("exactly one file path required")
	}
	config := &Configuration{
		FilePath:       args[0],
		Verbose:        *verboseFlag,
		Analyze:        *analyzeFlag || *analyzeFlagLong,
		Strip:          *stripFlag || *stripFlagLong,
		Obfuscate:      *obfuscateFlag || *obfuscateFlagLong,
		Compact:        *compactFlag || *compactFlagLong,
		CompactForce:   preCompactForce,
		StripForce:     preStripForce,
		ObfuscateForce: preObfForce,
		Regex:          common.FirstNonEmpty(*regexFlag, *regexFlagLong),
		Insert:         common.FirstNonEmpty(*insertFlag, *insertFlagLong),
		Overlay:        common.FirstNonEmpty(*overlayFlag, *overlayFlagLong),
		Pack:           common.FirstNonEmpty(*packFlag, *packFlagLong),
	}
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", config.FilePath)
	}
	if config.Analyze && (config.Strip || config.Obfuscate || config.Compact || config.Regex != "" || config.Insert != "" || config.Overlay != "" || config.Pack != "") {
		return nil, fmt.Errorf("analyze (-a) must be used alone")
	}
	// Se `-p` o `--pack` è stato specificato (anche con stringa vuota), segna come attivo
	for i, arg := range os.Args {
		if arg == "-p" || arg == "--pack" || strings.HasPrefix(arg, "-p=") || strings.HasPrefix(arg, "--pack=") {
			if arg == "-p" || arg == "--pack" {
				// Flag senza valore: usa default
				config.Pack = defaultPackOptions
			} else if config.Pack == "" {
				// Flag con = ma nessun valore: usa default
				config.Pack = defaultPackOptions
			}
			break
		}
		_ = i
	}

	if !(config.Analyze || config.Strip || config.Obfuscate || config.Compact || config.Regex != "" || config.Insert != "" || config.Overlay != "" || config.Pack != "") {
		return nil, fmt.Errorf("at least one operation required (-a, -s, -o, -c, -i, -l, -r, or -p)")
	}
	if config.Regex != "" {
		if _, err := regexp.Compile(config.Regex); err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %v", err)
		}
	}
	return config, nil
}

func determineFileType(filePath string) (bool, bool, error) {
	isPE, err := perw.IsPEFile(filePath)
	if err != nil {
		return false, false, fmt.Errorf("error checking PE file type: %v", err)
	}
	isELF := false
	if !isPE {
		isELF, err = elfrw.IsELFFile(filePath)
		if err != nil {
			return false, false, fmt.Errorf("error checking ELF file type: %v", err)
		}
	}
	if !isPE && !isELF {
		return false, false, fmt.Errorf("unsupported file type")
	}
	return isPE, isELF, nil
}

func getFileType(isPE bool) string {
	if isPE {
		return "PE"
	}
	return "ELF"
}

func plannedOperations(config *Configuration) []string {
	var ops []string
	if config.Strip {
		ops = append(ops, "strip")
	}
	if config.Compact {
		ops = append(ops, "compact")
	}
	if config.Obfuscate {
		ops = append(ops, "obfuscate")
	}
	if config.Insert != "" {
		ops = append(ops, "insert")
	}
	if config.Overlay != "" {
		ops = append(ops, "overlay")
	}
	if config.Regex != "" {
		ops = append(ops, "regex")
	}
	if config.Pack != "" {
		ops = append(ops, "pack")
	}
	return ops
}

func runOperations(config *Configuration) error {
	fmt.Printf("Processing file: %s\n", config.FilePath)

	isPE, isELF, err := determineFileType(config.FilePath)
	if err != nil {
		return err
	}
	if !isPE && !isELF {
		return fmt.Errorf("unsupported file type: %s", config.FilePath)
	}
	fmt.Printf("File type: %s\n", getFileType(isPE))

	if config.Analyze {
		return runAnalysis(config, isPE)
	}

	// Pack operation: must run LAST if enabled (cannot apply anything after packing)
	// Do not early-return here; we will invoke pack at the end of the pipeline.

	var operations []string
	if config.Strip {
		if err := runStrip(config, isPE); err != nil {
			return fmt.Errorf("strip operation failed: %v", err)
		}
		operations = append(operations, "strip")
	}
	if config.Compact {
		if err := runCompact(config, isPE); err != nil {
			return fmt.Errorf("compact operation failed: %v", err)
		}
		operations = append(operations, "compact")
	}
	if config.Obfuscate {
		if err := runObfuscate(config, isPE); err != nil {
			return err
		}
		operations = append(operations, "obfuscate")
	}
	if config.Insert != "" {
		if err := runInsert(config, isPE); err != nil {
			return err
		}
		operations = append(operations, "insert")
	}
	if config.Overlay != "" {
		if err := runOverlay(config, isPE); err != nil {
			return err
		}
		operations = append(operations, "overlay")
	}
	if config.Regex != "" {
		if err := runRegex(config, isPE); err != nil {
			return err
		}
		operations = append(operations, "regex")
	}
	// Pack must always be executed last if enabled
	if config.Pack != "" {
		if err := runPack(config); err != nil {
			return err
		}
		operations = append(operations, "pack")
	}
	if len(operations) > 0 {
		fmt.Printf("\nCompleted operations: %s\n", strings.Join(operations, ", "))
	}
	return nil
}

func runAnalysis(config *Configuration, isPE bool) error {
	fmt.Println("=== File Analysis ===")

	switch {
	case isPE:
		return perw.AnalyzePE(config.FilePath)
	default:
		return elfrw.AnalyzeELF(config.FilePath)
	}
}

func runStrip(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Strip Operations ===\nPerforming stripping...")
	var result *common.OperationResult
	if isPE {
		result = perw.StripPE(config.FilePath, config.StripForce)
	} else {
		result = elfrw.StripELF(config.FilePath, config.StripForce)
	}
	printOperationResult(getFileType(isPE), "Stripping", result)
	return nil
}

func runCompact(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Compact Operations ===\nPerforming file compaction...")
	var result *common.OperationResult
	if isPE {
		result = perw.CompactPE(config.FilePath, config.CompactForce)
	} else {
		result = elfrw.CompactELF(config.FilePath, config.CompactForce)
	}
	printOperationResult(getFileType(isPE), "Compaction", result)
	return nil
}

func runObfuscate(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Obfuscation Operations ===")
	var result *common.OperationResult
	if isPE {
		result = perw.ObfuscatePE(config.FilePath, config.ObfuscateForce)
	} else {
		result = elfrw.ObfuscateELF(config.FilePath, config.ObfuscateForce)
	}
	printOperationResult(getFileType(isPE), "Obfuscation", result)
	return nil
}

func runRegex(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Regex Operations ===")
	fmt.Printf("Applying custom regex pattern: %s\n", config.Regex)
	var result *common.OperationResult
	if isPE {
		result = perw.RegexPE(config.FilePath, config.Regex)
	} else {
		result = elfrw.RegexELF(config.FilePath, config.Regex)
	}
	printOperationResult(getFileType(isPE), "Regex", result)
	return nil
}

func runPack(config *Configuration) error {
	fmt.Println("\n=== Pack Operations ===")
	if err := pack.Pack(config.FilePath, config.Pack); err != nil {
		return fmt.Errorf("pack operation failed: %v", err)
	}
	return nil
}

func parseInsertSpec(spec string) (string, string, string, error) {
	idx := strings.Index(spec, ":")
	if idx == -1 {
		return "", "", "", fmt.Errorf("invalid format, expected name:data_or_file[:password]")
	}
	sectionName := spec[:idx]
	remainder := spec[idx+1:]
	if strings.TrimSpace(sectionName) == "" || remainder == "" {
		return "", "", "", fmt.Errorf("invalid format, expected name:data_or_file[:password]")
	}
	dataOrFile, password, err := splitValueAndPassword(remainder)
	if err != nil {
		return "", "", "", err
	}
	return sectionName, dataOrFile, password, nil
}

func parseOverlaySpec(spec string) (string, string, error) {
	if strings.TrimSpace(spec) == "" {
		return "", "", fmt.Errorf("invalid format, expected data_or_file[:password]")
	}
	return splitValueAndPassword(spec)
}

func splitValueAndPassword(value string) (string, string, error) {
	if strings.TrimSpace(value) == "" {
		return "", "", fmt.Errorf("invalid format, expected data_or_file[:password]")
	}
	separatorIdx := findPasswordSeparator(value)
	if separatorIdx == -1 {
		return value, "", nil
	}
	data := value[:separatorIdx]
	password := value[separatorIdx+1:]
	if data == "" || password == "" {
		return "", "", fmt.Errorf("invalid format, expected data_or_file[:password]")
	}
	return data, password, nil
}

func findPasswordSeparator(value string) int {
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] != ':' {
			continue
		}
		if isWindowsDriveSpec(value, i) {
			continue
		}
		return i
	}
	return -1
}

func isWindowsDriveSpec(value string, colonIndex int) bool {
	if colonIndex != 1 {
		return false
	}
	if colonIndex >= len(value)-1 {
		return false
	}
	r := rune(value[0])
	if !unicode.IsLetter(r) {
		return false
	}
	next := value[colonIndex+1]
	return next == '\\' || next == '/'
}

func runInsert(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Insert Operations ===")
	fmt.Printf("Inserting section: %s\n", config.Insert)
	sectionName, dataOrFile, password, err := parseInsertSpec(config.Insert)
	if err != nil {
		return err
	}
	var result *common.OperationResult
	if isPE {
		result = perw.InsertPE(config.FilePath, sectionName, dataOrFile, password)
	} else {
		result = elfrw.InsertELF(config.FilePath, sectionName, dataOrFile, password)
	}

	printOperationResult(getFileType(isPE), "Section insertion", result)
	return nil
}

func runOverlay(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Overlay Operations ===")
	fmt.Printf("Adding overlay: %s\n", config.Overlay)
	dataOrFile, password, err := parseOverlaySpec(config.Overlay)
	if err != nil {
		return err
	}
	var result *common.OperationResult
	if isPE {
		result = perw.OverlayPE(config.FilePath, dataOrFile, password)
	} else {
		result = elfrw.OverlayELF(config.FilePath, dataOrFile, password)
	}

	printOperationResult(getFileType(isPE), "Overlay insertion", result)
	return nil
}

func printOperationResult(fileType, operation string, result *common.OperationResult) {
	if result.Applied {
		fmt.Printf("✅ %s %s: %s\n", fileType, operation, result.FormatDetails())
	} else {
		fmt.Printf("❌ %s %s: %s\n", fileType, operation, result.Message)
	}
}

func printUsage() {
	prog := os.Args[0]
	fmt.Printf(`go-super-strip - Advanced Executable Stripping and Obfuscation Tool

USAGE:
	%[1]s [OPTIONS] <file>

DESCRIPTION:
	Process PE/ELF executables with stripping, obfuscation, and analysis capabilities.
	Operations are performed in strict order: strip -> compact -> obfuscate -> insert/overlay -> regex -> pack

OPTIONS:
	-a, --analyze            Analyze executable file structure and exit
	-s, --strip              StripAll debug and symbol sections
	                         Suboptions: -s=force=true|false (alias: -s=f=true|false)
	-c, --compact            Apply size reduction by removing sections
	                         Suboptions: -c=force=true|false (alias: -c=f=true|false)
	-o, --obfuscate          Apply obfuscation techniques
	                         Suboptions: -o=force=true|false (alias: -o=f=true|false)
	-r, --regex <pattern>    StripAll bytes matching a custom regex pattern
	-i, --insert <spec>      Add hex section (format: name:data_or_file[:password])
	                         - name:file.txt (file without password)
	                         - name:HelloWorld (string without password)  
	                         - name:file.txt:password123 (file with string password)
	                         - name:HelloWorld:deadbeef (string with hex password)
	                         Note: PE section names are limited to 8 characters
	-l, --overlay <spec>     Add data as overlay (format: data_or_file[:password])
	                         - file.txt (file without password)
	                         - HelloWorld (string without password)  
	                         - file.txt:password123 (file with string password)
	                         - HelloWorld:deadbeef (string with hex password)
	-p, --pack <options>     Pack executable with compression and polymorphic stub
	                         Options format: opt1=val1,opt2=val2
	                         Available options:
	                           compression=xz|lzma|none (default: xz)
	                           level=0-9 (default: 6)
	                           encryption=xor|aes-256-gcm|chacha20|none (default: aes-256-gcm)
	                           polymorphic=true|false (default: true)
	                           junkdensity=0.0-1.0 (default: 0.2)
	                           padding=true|false (default: true)
	                           inmemory=true|false (default: false)
	                           antidebug=true|false (default: false)
	                           antivm=true|false (default: false)
	                           verbose=true|false (default: false)
	                         Note (Windows/PowerShell): quote the -p value to avoid shell parsing issues with commas.
                        Example: gosstrip.exe -p="compression=lzma,level=9,encryption=chacha20" file.exe
	                         Or use stop-parsing operator: gosstrip.exe --%% -p=compression=lzma,level=9,encryption=chacha20 file.exe
	-v                       Enable verbose output
	-h                       Show this help


EXAMPLES:
	%[1]s -a bin                 		  		# Analyze PE file structure
	%[1]s -s bin                 		  		# StripAll debug sections
	%[1]s -c bin              					# Compact file (remove sections)
	%[1]s -o bin              		  		# Apply obfuscation techniques
	%[1]s -p bin              		  		# Pack with default options
	%[1]s -p=compression=xz,level=9,encryption=aes-256-gcm bin  # Pack with custom options
	%[1]s -p=polymorphic=true,junkdensity=0.5,inmemory=true bin # Pack with polymorphism
	%[1]s -s -c -o bin        			    		# StripAll, compact, and obfuscate (full pipeline)
	%[1]s -s -sf bin            		    		# StripAll with risky operations (relocations, etc.)
	%[1]s -o -of bin               			# Obfuscation with risky operations
	%[1]s -s -r 'UPX!' bin        				# StripAll built-in rules, then custom regex 'UPX!'
	%[1]s -i '.custom:data.bin' bin 			# Add hex section from file
	%[1]s -i '.custom:HelloWorld' bin 			# Add hex section from string
	%[1]s -i '.secret:data.bin:pass123' bin 	# Add encrypted hex section
	%[1]s -l 'data.bin' bin 				# Add overlay from file
	%[1]s -l 'HelloWorld' bin 				# Add overlay from string
	%[1]s -l 'data.bin:pass123' bin 			# Add encrypted overlay

`, prog)
}
