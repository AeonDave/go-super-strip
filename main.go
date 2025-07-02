package main

import (
	"flag"
	"fmt"
	"gosstrip/common"
	"gosstrip/elfrw"
	"gosstrip/perw"
	"os"
	"regexp"
	"strings"
)

type Configuration struct {
	FilePath  string
	Verbose   bool
	Analyze   bool   // -a: Analyze file structure only (standalone)
	Strip     bool   // -s: Strip info, metadata and sections
	Obfuscate bool   // -o: Apply obfuscation techniques
	Compact   bool   // -c: Apply file size reduction
	Insert    string // -i: Add section (format: name:filepath[:password])
	Overlay   string // -l: Add overlay (format: filepath[:password])
	Regex     string // -r: Strip bytes matching regex pattern
	Force     bool   // -f: Apply risky operations for -s, -c, -o
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

	// Modifiers
	forceFlag     = flag.Bool("f", false, "Apply risky operations to -s, -c, or -o")
	forceFlagLong = flag.Bool("force", false, "Apply risky operations to -s, -c, or -o")

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
		FilePath:  args[0],
		Verbose:   *verboseFlag,
		Analyze:   *analyzeFlag || *analyzeFlagLong,
		Strip:     *stripFlag || *stripFlagLong,
		Obfuscate: *obfuscateFlag || *obfuscateFlagLong,
		Compact:   *compactFlag || *compactFlagLong,
		Force:     *forceFlag || *forceFlagLong,
		Regex:     common.FirstNonEmpty(*regexFlag, *regexFlagLong),
		Insert:    common.FirstNonEmpty(*insertFlag, *insertFlagLong),
		Overlay:   common.FirstNonEmpty(*overlayFlag, *overlayFlagLong),
	}
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", config.FilePath)
	}
	if config.Analyze && (config.Strip || config.Obfuscate || config.Compact || config.Regex != "" || config.Insert != "" || config.Overlay != "" || config.Force) {
		return nil, fmt.Errorf("analyze (-a) must be used alone")
	}
	if config.Force && !(config.Strip || config.Compact || config.Obfuscate) {
		return nil, fmt.Errorf("force (-f) can only be used with strip (-s), compact (-c), or obfuscate (-o)")
	}
	if !(config.Analyze || config.Strip || config.Obfuscate || config.Compact || config.Regex != "" || config.Insert != "" || config.Overlay != "") {
		return nil, fmt.Errorf("at least one operation required (-s, -o, -c, -i, -l, or -r)")
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

	var operations []string
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
	if config.Regex != "" {
		if err := runRegex(config, isPE); err != nil {
			return err
		}
		operations = append(operations, "regex")
	}
	if len(operations) > 0 {
		fmt.Printf("Completed operations: %s\n", strings.Join(operations, ", "))
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
	fmt.Println("\n=== StripAll Operations ===\nPerforming stripping...")
	var result *common.OperationResult
	if isPE {
		result = perw.StripPE(config.FilePath, config.Force)
	} else {
		result = elfrw.StripELF(config.FilePath, config.Force)
	}
	printOperationResult(getFileType(isPE), "Stripping", result)
	return nil
}

func runCompact(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Compact Operations ===\nPerforming file compaction...")
	var result *common.OperationResult
	if isPE {
		result = perw.CompactPE(config.FilePath, config.Force)
	} else {
		result = elfrw.CompactELF(config.FilePath, config.Force)
	}
	printOperationResult(getFileType(isPE), "Compaction", result)
	return nil
}

func runObfuscate(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Obfuscation Operations ===")
	var result *common.OperationResult
	if isPE {
		result = perw.ObfuscatePE(config.FilePath, config.Force)
	} else {
		result = elfrw.ObfuscateELF(config.FilePath, config.Force)
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
	printOperationResult(getFileType(isPE), "Obfuscation", result)
	return nil
}

func runInsert(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Insert Operations ===")
	fmt.Printf("Inserting section: %s\n", config.Insert)

	parts := strings.Split(config.Insert, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid format, expected name:data_or_file[:password]")
	}

	sectionName, dataOrFile := parts[0], parts[1]
	password := ""
	if len(parts) > 2 {
		password = parts[2]
	}

	var result *common.OperationResult
	if isPE {
		result = perw.InsertPE(config.FilePath, sectionName, dataOrFile, password)
	} else {
		result = elfrw.InsertELF(config.FilePath, sectionName, dataOrFile, password)
	}

	printOperationResult(getFileType(isPE), "Sector insertion", result)
	return nil
}

func runOverlay(config *Configuration, isPE bool) error {
	fmt.Println("\n=== Overlay Operations ===")
	fmt.Printf("Adding overlay: %s\n", config.Overlay)

	parts := strings.Split(config.Overlay, ":")
	if len(parts) < 1 {
		return fmt.Errorf("invalid format, expected data_or_file[:password]")
	}

	dataOrFile := parts[0]
	password := ""
	if len(parts) > 1 {
		password = parts[1]
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
		fmt.Printf("✅ %s %s: %s\n", fileType, operation, result.Message)
	} else {
		fmt.Printf("❌ %s %s: %s\n", fileType, operation, result.Message)
	}
}

func printUsage() {
	fmt.Printf(`go-super-strip - Advanced Executable Stripping and Obfuscation Tool

USAGE:
	%s [OPTIONS] <file>

DESCRIPTION:
	Process PE/ELF executables with stripping, obfuscation, and analysis capabilities.
	Operations are performed in strict order: insert/overlay -> strip -> compact -> obfuscate -> regex

OPTIONS:
	-a, --analyze        Analyze executable file structure and exit
	-s, --strip          StripAll debug and symbol sections
	-c, --compact        Apply size reduction by removing sections
	-f, --force          Apply risky operations to -s, -c, or -o
	-o, --obfuscate      Apply obfuscation techniques
	-r, --regex <pattern> StripAll bytes matching a custom regex pattern
	-i, --insert <spec>  Add hex section (format: name:data_or_file[:password])
	                     - name:file.txt (file without password)
	                     - name:HelloWorld (string without password)  
	                     - name:file.txt:password123 (file with string password)
	                     - name:HelloWorld:deadbeef (string with hex password)
	                     Note: PE section names are limited to 8 characters
	-l, --overlay <spec> Add data as overlay (format: data_or_file[:password])
	                     - file.txt (file without password)
	                     - HelloWorld (string without password)  
	                     - file.txt:password123 (file with string password)
	                     - HelloWorld:deadbeef (string with hex password)
	-v                   Enable verbose output
	-h                   Show this help

EXAMPLES:
	%s -a bin                		  		# Analyze PE file structure
	%s -s bin                		  		# StripAll debug sections
	%s -c bin              					# Compact file (remove sections)
	%s -o bin              		 			# Apply obfuscation techniques
	%s -s -c -o bin        		 	   		# StripAll, compact, and obfuscate (full pipeline)
	%s -s -f bin            		   		# StripAll with risky operations (relocations, etc.)
	%s -c -f bin               				# Compact with risky operations
	%s -s -r 'UPX!' bin        				# StripAll built-in rules, then custom regex 'UPX!'
	%s -i '.custom:data.bin' bin 			# Add hex section from file
	%s -i '.custom:HelloWorld' bin 			# Add hex section from string
	%s -i '.secret:data.bin:pass123' bin 	# Add encrypted hex section
	%s -l 'data.bin' bin 					# Add overlay from file
	%s -l 'HelloWorld' bin 					# Add overlay from string
	%s -l 'data.bin:pass123' bin 			# Add encrypted overlay

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
