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
	FilePath string
	Verbose  bool

	// Core operation flags (-a, -s, -o, -c, -i, -r)
	Analyze   bool   // -a: Analyze file structure only (standalone)
	Strip     bool   // -s: Strip info, metadata and sections
	Obfuscate bool   // -o: Apply obfuscation techniques
	Compact   bool   // -c: Apply file size reduction
	Insert    string // -i: Add section (format: name:filepath[:password])
	Regex     string // -r: Strip bytes matching regex pattern

	// Modifier flags
	Force bool // -f: Apply risky operations for -s, -c, -o
}

var (
	// Core techniques
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

	regexFlag     = flag.String("r", "", "StripAll bytes matching regex pattern")
	regexFlagLong = flag.String("regex", "", "StripAll bytes matching regex pattern")

	// Modifiers
	forceFlag     = flag.Bool("f", false, "Apply risky operations to -s, -c, or -o")
	forceFlagLong = flag.Bool("force", false, "Apply risky operations to -s, -c, or -o")

	// Other
	verboseFlag = flag.Bool("v", false, "Enable verbose output")
	helpFlag    = flag.Bool("h", false, "Show this help")
)

func init() {
	flag.Usage = printUsage
}

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

	// Set up debug logging
	if config.Verbose {
		elfrw.SetDebugLogger(func(format string, args ...interface{}) {
			fmt.Printf("DEBUG: "+format+"\n", args...)
		})
	}

	// Execute operations
	if err := runOperations(config); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// parseArgs parses command line arguments and returns configuration
func parseArgs() (*Configuration, error) {
	flag.Parse()

	// Show help if requested
	if *helpFlag {
		printUsage()
		os.Exit(0)
	}

	// Ensure exactly one file path is provided
	args := flag.Args()
	if len(args) != 1 {
		return nil, fmt.Errorf("exactly one file path required")
	}

	// Initialize configuration
	config := &Configuration{
		FilePath:  args[0],
		Verbose:   *verboseFlag,
		Analyze:   *analyzeFlag || *analyzeFlagLong,
		Strip:     *stripFlag || *stripFlagLong,
		Obfuscate: *obfuscateFlag || *obfuscateFlagLong,
		Compact:   *compactFlag || *compactFlagLong,
		Force:     *forceFlag || *forceFlagLong,
		Regex:     firstNonEmpty(*regexFlag, *regexFlagLong),
		Insert:    firstNonEmpty(*insertFlag, *insertFlagLong),
	}

	// Validate file existence
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", config.FilePath)
	}

	// Ensure analyze is used alone
	if config.Analyze && (config.Strip || config.Obfuscate || config.Compact || config.Regex != "" || config.Insert != "" || config.Force) {
		return nil, fmt.Errorf("analyze (-a) must be used alone")
	}

	// Validate force usage
	if config.Force && !(config.Strip || config.Compact || config.Obfuscate) {
		return nil, fmt.Errorf("force (-f) can only be used with strip (-s), compact (-c), or obfuscate (-o)")
	}

	// Ensure at least one operation is specified
	if !(config.Analyze || config.Strip || config.Obfuscate || config.Compact || config.Regex != "" || config.Insert != "") {
		return nil, fmt.Errorf("at least one operation required (-s, -o, -c, -i, or -r)")
	}

	// Validate regex pattern
	if config.Regex != "" {
		if _, err := regexp.Compile(config.Regex); err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %v", err)
		}
	}

	return config, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
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

	// Step 1: Insert
	if config.Insert != "" {
		if err := runInsert(config, isPE); err != nil {
			return err
		}
		operations = append(operations, "insert")
	}

	// Step 2: StripAll
	if config.Strip {
		if err := runStrip(config, isPE); err != nil {
			return fmt.Errorf("strip operation failed: %v", err)
		}
		operations = append(operations, "strip")
	}

	// Step 3: Compact
	if config.Compact {
		if err := runCompact(config, isPE); err != nil {
			return fmt.Errorf("compact operation failed: %v", err)
		}
		operations = append(operations, "compact")
	}

	// Step 4: Obfuscate
	if config.Obfuscate {
		if err := runObfuscate(config, isPE); err != nil {
			return err
		}
		operations = append(operations, "obfuscate")
	}

	// Step 5: Regex
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
		result = elfrw.StripELFDetailed(config.FilePath, false, config.Force)
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
		result = elfrw.StripELFDetailed(config.FilePath, true, config.Force)
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

	if isPE {
		result := perw.RegexPE(config.FilePath, config.Regex)
		if result.Applied {
			fmt.Printf("✅ %s Regex Stripping: %s\n", getFileType(isPE), result.Message)
		} else {
			fmt.Printf("❌ %s Regex Stripping: %s\n", getFileType(isPE), result.Message)
		}
	} else {
		fmt.Printf("⚠️  %s Custom Regex: not yet implemented for ELF files\n", getFileType(isPE))
	}
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

	fileType := getFileType(isPE)

	var result *common.OperationResult
	if isPE {
		result = perw.InsertPE(config.FilePath, sectionName, dataOrFile, password)
	} else {
		result = elfrw.AddHexSectionDetailed(config.FilePath, sectionName, dataOrFile, password)
	}

	printInsertResult(fileType, result)
	return nil
}

func printOperationResult(fileType, operation string, result *common.OperationResult) {
	if result.Applied {
		fmt.Printf("✅ %s %s: %s\n", fileType, operation, result.Message)
	} else {
		fmt.Printf("❌ %s %s: %s\n", fileType, operation, result.Message)
	}
}

func printInsertResult(fileType string, result *common.OperationResult) {
	if result.Applied {
		fmt.Printf("✅ %s Section Insertion: %s\n", fileType, result.Message)
	} else {
		fmt.Printf("❌ %s Section Insertion: %s\n", fileType, result.Message)
	}
}

func printUsage() {
	fmt.Printf(`go-super-strip - Advanced Executable Stripping and Obfuscation Tool

USAGE:
	%s [OPTIONS] <file>

DESCRIPTION:
	Process PE/ELF executables with stripping, obfuscation, and analysis capabilities.
	Operations are performed in strict order: insert -> strip -> compact -> obfuscate -> regex

OPTIONS:
	-s, --strip          StripAll debug and symbol sections
	-c, --compact        Apply size reduction by removing sections
	-f, --force          Apply risky operations to -s, -c, or -o
	-o, --obfuscate      Apply obfuscation techniques
	-r, --regex <pattern> StripAll bytes matching a custom regex pattern
	-a, --analyze        Analyze executable file structure and exit
	-i, --insert <spec>  Add hex section (format: name:data_or_file[:password])
	                     - name:file.txt (file without password)
	                     - name:HelloWorld (string without password)  
	                     - name:file.txt:password123 (file with string password)
	                     - name:HelloWorld:deadbeef (string with hex password)
	                     Note: PE section names are limited to 8 characters
	-v                   Enable verbose output
	-h                   Show this help

EXAMPLES:
	%s -a program                		  	# Analyze PE file structure
	%s -s program                		  	# StripAll debug sections
	%s -c program              				# Compact file (remove sections)
	%s -o program              		 		# Apply obfuscation techniques
	%s -s -c -o program        		 	   	# StripAll, compact, and obfuscate (full pipeline)
	%s -s -f program            		   	# StripAll with risky operations (relocations, etc.)
	%s -c -f program               			# Compact with risky operations
	%s -s -r 'UPX!' program        			# StripAll built-in rules, then custom regex 'UPX!'
	%s -i 'custom:data.bin' program 		# Add hex section from file
	%s -i 'custom:HelloWorld' program 		# Add hex section from string
	%s -i 'secret:data.bin:pass123' program # Add encrypted hex section

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
