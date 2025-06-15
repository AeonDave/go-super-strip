package main

import (
	"flag"
	"fmt"
	"gosstrip/elfrw"
	"gosstrip/perw"
	"os"
	"regexp"
	"strings"
)

// Configuration holds all program settings
type Configuration struct {
	FilePath string
	Verbose  bool

	// Operation flags
	Strip     bool   // -s/--strip: Strip debug/symbol sections
	Obfuscate bool   // -o/--obfuscate: Apply obfuscation techniques
	Regex     string // -r/--regex: Strip bytes matching regex pattern
	Analyze   bool   // -a/--analyze: Analyze file structure only
	Insert    string // -i/--insert: Add section (format: name:filepath)
}

// Global flags
var (
	stripFlag     = flag.Bool("s", false, "Strip debug and symbol sections")
	stripFlagLong = flag.Bool("strip", false, "Strip debug and symbol sections")

	obfuscateFlag     = flag.Bool("o", false, "Apply obfuscation techniques (section names, etc.)")
	obfuscateFlagLong = flag.Bool("obfuscate", false, "Apply obfuscation techniques (section names, etc.)")

	regexFlag     = flag.String("r", "", "Strip bytes matching regex pattern")
	regexFlagLong = flag.String("regex", "", "Strip bytes matching regex pattern")

	analyzeFlag     = flag.Bool("a", false, "Analyze executable file structure and exit")
	analyzeFlagLong = flag.Bool("analyze", false, "Analyze executable file structure and exit")

	insertFlag     = flag.String("i", "", "Add section (format: name:filepath)")
	insertFlagLong = flag.String("insert", "", "Add section (format: name:filepath)")

	verboseFlag = flag.Bool("v", false, "Enable verbose output")
)

func init() {
	flag.Usage = printUsage
}

func main() {
	// Check for help first
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" || arg == "-help" || arg == "help" {
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

	// Get file path from non-flag arguments
	args := flag.Args()
	if len(args) != 1 {
		return nil, fmt.Errorf("exactly one file path required")
	}

	config := &Configuration{
		FilePath:  args[0],
		Verbose:   *verboseFlag,
		Strip:     *stripFlag || *stripFlagLong,
		Obfuscate: *obfuscateFlag || *obfuscateFlagLong,
		Analyze:   *analyzeFlag || *analyzeFlagLong,
	}

	// Handle regex flag
	if *regexFlag != "" {
		config.Regex = *regexFlag
	} else if *regexFlagLong != "" {
		config.Regex = *regexFlagLong
	}

	// Handle insert flag
	if *insertFlag != "" {
		config.Insert = *insertFlag
	} else if *insertFlagLong != "" {
		config.Insert = *insertFlagLong
	}

	// Validate file exists
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", config.FilePath)
	}

	// If analyze is set, other operations should be ignored
	if config.Analyze {
		if config.Strip || config.Obfuscate || config.Regex != "" || config.Insert != "" {
			fmt.Println("Note: -a/--analyze specified, ignoring other operation flags")
		}
		return config, nil
	}

	// At least one operation must be specified (unless analyze)
	if !config.Strip && !config.Obfuscate && config.Regex == "" && config.Insert == "" {
		return nil, fmt.Errorf("at least one operation flag required (-s, -o, -r, or -i)")
	}

	return config, nil
}

// runOperations executes the requested operations in order
func runOperations(config *Configuration) error {
	fmt.Printf("Processing file: %s\n", config.FilePath)

	// Determine file type
	isPE, err := perw.IsPEFile(config.FilePath)
	if err != nil {
		return fmt.Errorf("failed to check file type: %v", err)
	}

	isELF := false
	if !isPE {
		isELF, err = elfrw.IsELFFile(config.FilePath)
		if err != nil {
			return fmt.Errorf("failed to check file type: %v", err)
		}
	}

	if !isPE && !isELF {
		return fmt.Errorf("unsupported file type (not PE or ELF)")
	}

	fileType := "ELF"
	if isPE {
		fileType = "PE"
	}
	fmt.Printf("File type: %s\n", fileType)

	// If analyze only, run analysis and exit
	if config.Analyze {
		return runAnalysis(config, isPE, isELF)
	}

	// Execute operations in order: Strip → Obfuscate → Regex → Insert
	var operations []string

	// 1. Strip operations
	if config.Strip {
		if err := runStrip(config, isPE, isELF); err != nil {
			return fmt.Errorf("strip operation failed: %v", err)
		}
		operations = append(operations, "strip")
	}

	// 2. Obfuscate operations
	if config.Obfuscate {
		if err := runObfuscate(config, isPE, isELF); err != nil {
			return fmt.Errorf("obfuscate operation failed: %v", err)
		}
		operations = append(operations, "obfuscate")
	}

	// 3. Regex operations
	if config.Regex != "" {
		if err := runRegex(config, isPE, isELF); err != nil {
			return fmt.Errorf("regex operation failed: %v", err)
		}
		operations = append(operations, "regex")
	}

	// 4. Insert operations (always last)
	if config.Insert != "" {
		if err := runInsert(config, isPE, isELF); err != nil {
			return fmt.Errorf("insert operation failed: %v", err)
		}
		operations = append(operations, "insert")
	}

	fmt.Printf("Completed operations: %s\n", strings.Join(operations, ", "))
	return nil
}

// runAnalysis performs file analysis
func runAnalysis(config *Configuration, isPE, isELF bool) error {
	fmt.Println("=== File Analysis ===")

	if isPE {
		return perw.AnalyzePE(config.FilePath)
	} else if isELF {
		return elfrw.AnalyzeELF(config.FilePath)
	}

	return fmt.Errorf("unsupported file type")
}

// runStrip performs stripping operations
func runStrip(config *Configuration, isPE, isELF bool) error {
	fmt.Println("=== Strip Operations ===")

	if isPE {
		// PE stripping: debug sections and symbols
		fmt.Println("Stripping debug sections...")
		result := perw.StripDebugSectionsDetailed(config.FilePath)
		fmt.Printf("Strip debug sections: %s\n", result.String())

		fmt.Println("Stripping symbol sections...")
		result = perw.StripSymbolSectionsDetailed(config.FilePath)
		fmt.Printf("Strip symbol sections: %s\n", result.String())
	} else if isELF {
		// ELF stripping: debug sections and symbols
		fmt.Println("Stripping debug sections...")
		result := elfrw.StripDebugSectionsDetailed(config.FilePath)
		fmt.Printf("Strip debug sections: %s\n", result.String())

		fmt.Println("Stripping symbol sections...")
		result = elfrw.StripSymbolSectionsDetailed(config.FilePath)
		fmt.Printf("Strip symbol sections: %s\n", result.String())
	}

	return nil
}

// runObfuscate performs obfuscation operations
func runObfuscate(config *Configuration, isPE, isELF bool) error {
	fmt.Println("=== Obfuscation Operations ===")

	if isPE {
		// PE obfuscation techniques
		techniques := []struct {
			name string
			fn   func(string) *perw.OperationResult
		}{
			{"Section names", perw.ObfuscateSectionNamesDetailed},
			{"Base addresses", perw.ObfuscateBaseAddressesDetailed},
			{"Load configuration", perw.ObfuscateLoadConfigurationDetailed},
			{"Import table", perw.ObfuscateImportTableDetailed},
			{"Import names", perw.ObfuscateImportNamesDetailed},
			{"Rich header", perw.ObfuscateRichHeaderDetailed},
			{"Resource directory", perw.ObfuscateResourceDirectoryDetailed},
			{"Export table", perw.ObfuscateExportTableDetailed},
		}

		for _, tech := range techniques {
			fmt.Printf("Obfuscating %s...\n", tech.name)
			result := tech.fn(config.FilePath)
			fmt.Printf("Obfuscate %s: %s\n", tech.name, result.String())
		}
	} else if isELF {
		// Check if this is a Go binary before any obfuscation
		isGoBinary, err := elfrw.IsGoBinary(config.FilePath)
		if err != nil {
			return fmt.Errorf("failed to check if Go binary: %v", err)
		} // ELF obfuscation techniques
		techniques := []struct {
			name      string
			fn        func(string) *elfrw.OperationResult
			skipForGo bool
		}{
			{"Section names", elfrw.ObfuscateSectionNamesDetailed, false},
			{"Base addresses", elfrw.ObfuscateBaseAddressesDetailed, true}, // Skip for Go binaries
		}

		for _, tech := range techniques {
			if tech.skipForGo && isGoBinary {
				fmt.Printf("Obfuscating %s...\n", tech.name)
				fmt.Printf("Obfuscate %s: SKIPPED (Go binary - would break runtime)\n", tech.name)
				continue
			}

			fmt.Printf("Obfuscating %s...\n", tech.name)
			result := tech.fn(config.FilePath)
			fmt.Printf("Obfuscate %s: %s\n", tech.name, result.String())
		}

		// Apply additional obfuscation for non-Go binaries only
		if !isGoBinary {
			fmt.Printf("Obfuscating All obfuscation...\n")
			result := elfrw.ObfuscateAllDetailed(config.FilePath)
			fmt.Printf("Obfuscate All obfuscation: %s\n", result.String())
		}
	}

	return nil
}

// runRegex performs regex-based byte stripping
func runRegex(config *Configuration, isPE, isELF bool) error {
	fmt.Println("=== Regex Operations ===")

	// Compile regex pattern
	regex, err := regexp.Compile(config.Regex)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %v", err)
	}

	fmt.Printf("Applying regex pattern: %s\n", config.Regex)

	if isPE {
		if err := perw.StripRegexBytes(config.FilePath, regex); err != nil {
			fmt.Printf("Regex stripping: SKIPPED (%v)\n", err)
		} else {
			fmt.Println("Regex stripping: APPLIED")
		}
	} else if isELF {
		if err := elfrw.StripRegexBytes(config.FilePath, regex); err != nil {
			fmt.Printf("Regex stripping: SKIPPED (%v)\n", err)
		} else {
			fmt.Println("Regex stripping: APPLIED")
		}
	}

	return nil
}

// runInsert performs section insertion
func runInsert(config *Configuration, isPE, isELF bool) error {
	fmt.Println("=== Insert Operations ===")

	// Parse section specification: name:filepath
	parts := strings.SplitN(config.Insert, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid section format, expected 'name:filepath'")
	}

	sectionName := parts[0]
	sourceFile := parts[1]

	// Validate source file exists
	if _, err := os.Stat(sourceFile); os.IsNotExist(err) {
		return fmt.Errorf("source file does not exist: %s", sourceFile)
	}

	fmt.Printf("Adding section '%s' from file: %s\n", sectionName, sourceFile)

	if isPE {
		if err := perw.AddSection(config.FilePath, sectionName, sourceFile); err != nil {
			fmt.Printf("Add section: SKIPPED (%v)\n", err)
		} else {
			fmt.Println("Add section: APPLIED")
		}
	} else if isELF {
		if err := elfrw.AddSection(config.FilePath, sectionName, sourceFile); err != nil {
			fmt.Printf("Add section: SKIPPED (%v)\n", err)
		} else {
			fmt.Println("Add section: APPLIED")
		}
	}

	return nil
}

// printUsage prints the help message
func printUsage() {
	fmt.Printf(`go-super-strip - Advanced Executable Stripping and Obfuscation Tool

USAGE:
    %s [OPTIONS] <file>

DESCRIPTION:
    Process PE/ELF executables with stripping, obfuscation, and analysis capabilities.
    Operations are performed in order: strip → obfuscate → regex → insert

OPTIONS:
    -s, --strip          Strip debug and symbol sections
    -o, --obfuscate      Apply obfuscation techniques (section names, metadata, etc.)
    -r, --regex <pattern> Strip bytes matching regex pattern
    -a, --analyze        Analyze executable file structure and exit (ignores other flags)
    -i, --insert <spec>  Add section (format: name:filepath, performed last)
    
    -v                   Enable verbose output
    -h                   Show this help

EXAMPLES:
    %s -a program                    	# Analyze PE file structure
    %s -s program                    	# Strip debug/symbol sections
    %s -o program                   	# Apply obfuscation techniques
    %s -s -o program                	# Strip and obfuscate
    %s -r "golang.*" program        	# Strip bytes matching regex
    %s -i "custom:data.bin" program  	# Add section from file
    %s -s -o -i "data:payload.bin" prog # Strip, obfuscate, and add section

SUPPORTED FILES:
    - PE files (.exe, .dll)
    - ELF files (Linux/Unix executables)

NOTE:
    - Each operation reports if it was applied or skipped (with reason)
    - Use -a alone for analysis without modification
    - Operations are performed in fixed order for predictable results
    - Insert operations are always performed last
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
