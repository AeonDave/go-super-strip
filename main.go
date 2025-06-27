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

// Configuration holds all program settings
type Configuration struct {
	FilePath string
	Verbose  bool

	// Core operation flags (-s, -o, -c, -i, -r)
	Strip     bool   // -s: Strip debug and symbol sections
	Obfuscate bool   // -o: Apply obfuscation techniques
	Compact   bool   // -c: Apply file size reduction
	Insert    string // -i: Add section (format: name:filepath[:password])
	Regex     string // -r: Strip bytes matching regex pattern

	// Modifier flags
	Force   bool // -f: Apply risky operations for -s, -c, -o
	Analyze bool // -a: Analyze file structure only (standalone)
}

// Global flags - organized by technique
var (
	// Core techniques
	stripFlag     = flag.Bool("s", false, "Strip debug and symbol sections")
	stripFlagLong = flag.Bool("strip", false, "Strip debug and symbol sections")

	obfuscateFlag     = flag.Bool("o", false, "Apply obfuscation techniques")
	obfuscateFlagLong = flag.Bool("obfuscate", false, "Apply obfuscation techniques")

	compactFlag     = flag.Bool("c", false, "Apply file size reduction by removing sections")
	compactFlagLong = flag.Bool("compact", false, "Apply file size reduction by removing sections")

	insertFlag     = flag.String("i", "", "Add hex section (format: name:data_or_file[:password])")
	insertFlagLong = flag.String("insert", "", "Add hex section (format: name:data_or_file[:password])")

	regexFlag     = flag.String("r", "", "Strip bytes matching regex pattern")
	regexFlagLong = flag.String("regex", "", "Strip bytes matching regex pattern")

	// Modifiers
	forceFlag     = flag.Bool("f", false, "Apply risky operations to -s, -c, or -o")
	forceFlagLong = flag.Bool("force", false, "Apply risky operations to -s, -c, or -o")

	analyzeFlag     = flag.Bool("a", false, "Analyze executable file structure and exit")
	analyzeFlagLong = flag.Bool("analyze", false, "Analyze executable file structure and exit")

	// Other
	verboseFlag = flag.Bool("v", false, "Enable verbose output")
	helpFlag    = flag.Bool("h", false, "Show this help")
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

	// Check for help flag
	if *helpFlag {
		printUsage()
		os.Exit(0)
	}

	// Get file path from non-flag arguments
	args := flag.Args()
	if len(args) != 1 {
		return nil, fmt.Errorf("exactly one file path required")
	}

	config := &Configuration{
		FilePath: args[0],
		Verbose:  *verboseFlag,

		// Core techniques (can be standalone or combined)
		Strip:     *stripFlag || *stripFlagLong,
		Obfuscate: *obfuscateFlag || *obfuscateFlagLong,
		Compact:   *compactFlag || *compactFlagLong,

		// Modifiers
		Force:   *forceFlag || *forceFlagLong,
		Analyze: *analyzeFlag || *analyzeFlagLong,
	}

	// Handle regex flag (can be standalone or combined)
	if *regexFlag != "" {
		config.Regex = *regexFlag
	} else if *regexFlagLong != "" {
		config.Regex = *regexFlagLong
	}

	// Handle insert flag (can be standalone or combined)
	if *insertFlag != "" {
		config.Insert = *insertFlag
	} else if *insertFlagLong != "" {
		config.Insert = *insertFlagLong
	}

	// Validate file exists
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", config.FilePath)
	}

	// If analyze is set, it must be used alone
	if config.Analyze {
		if config.Strip || config.Obfuscate || config.Compact || config.Regex != "" || config.Insert != "" || config.Force {
			return nil, fmt.Errorf("analyze (-a) must be used alone")
		}
		return config, nil
	}

	// Validate force constraint: -f can only be used with -s, -c, or -o
	if config.Force {
		if !config.Strip && !config.Compact && !config.Obfuscate {
			return nil, fmt.Errorf("force (-f) can only be used with strip (-s), compact (-c), or obfuscate (-o)")
		}
	}

	// At least one operation must be specified
	if !config.Strip && !config.Obfuscate && !config.Compact && config.Regex == "" && config.Insert == "" {
		return nil, fmt.Errorf("at least one operation required (-s, -o, -c, -i, or -r)")
	}

	// Validate regex pattern if provided
	if config.Regex != "" {
		if _, err := regexp.Compile(config.Regex); err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %v", err)
		}
	}

	return config, nil
}

// determineFileType checks if the file is PE or ELF
func determineFileType(filePath string) (isPE, isELF bool, err error) {
	isPE, err = perw.IsPEFile(filePath)
	if err != nil {
		return false, false, fmt.Errorf("failed to check PE file type: %v", err)
	}

	if !isPE {
		isELF, err = elfrw.IsELFFile(filePath)
		if err != nil {
			return false, false, fmt.Errorf("failed to check ELF file type: %v", err)
		}
	}

	if !isPE && !isELF {
		return false, false, fmt.Errorf("unsupported file type (not PE or ELF)")
	}

	return isPE, isELF, nil
}

// runOperations executes the requested operations in order
func runOperations(config *Configuration) error {
	fmt.Printf("Processing file: %s\n", config.FilePath)

	// Determine file type
	isPE, isELF, err := determineFileType(config.FilePath)
	if err != nil {
		return err
	}

	fileType := "ELF"
	if isPE {
		fileType = "PE"
	}
	fmt.Printf("File type: %s\n", fileType)

	// Handle special case: analysis only
	if config.Analyze {
		return runAnalysis(config, isPE, isELF)
	}

	// Execute operations in strict order:
	// 1. Strip/Compact (can be combined)
	// 2. Obfuscate
	// 3. Regex
	// 4. Insert (always last)
	var operations []string

	// Step 1: Strip and/or Compact operations
	if config.Strip || config.Compact {
		if err := runStripCompact(config, isPE, isELF); err != nil {
			return fmt.Errorf("stripping/compact operation failed: %v", err)
		}

		if config.Strip && config.Compact {
			operations = append(operations, "strip+compact")
		} else if config.Strip {
			operations = append(operations, "strip")
		} else if config.Compact {
			operations = append(operations, "compact")
		}
	}

	// Step 2: Obfuscate operations
	if config.Obfuscate {
		if err := runObfuscate(config, isPE, isELF); err != nil {
			return err
		}
		operations = append(operations, "obfuscate")
	}

	// Step 3: Regex operations
	if config.Regex != "" {
		if err := runRegex(config, isPE, isELF); err != nil {
			return err
		}
		operations = append(operations, "regex")
	}

	// Step 4: Insert operations (always last)
	if config.Insert != "" {
		if err := runInsert(config, isPE, isELF); err != nil {
			return err
		}
		operations = append(operations, "insert")
	}

	if len(operations) > 0 {
		fmt.Printf("Completed operations: %s\n", strings.Join(operations, ", "))
	}

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

// runStripCompact performs stripping and/or compaction operations
func runStripCompact(config *Configuration, isPE, isELF bool) error {
	if config.Strip && config.Compact {
		fmt.Println("\n=== Strip + Compact Operations ===")
		fmt.Println("Performing comprehensive stripping with compaction...")
	} else if config.Strip {
		fmt.Println("\n=== Strip Operations ===")
		fmt.Println("Performing comprehensive stripping...")
	} else if config.Compact {
		fmt.Println("\n=== Compact Operations ===")
		fmt.Println("Performing file compaction...")
	}

	fileType := "ELF"
	if isPE {
		fileType = "PE"
	}

	// Execute strip operation if requested
	if config.Strip {
		if isPE {
			result := perw.StripPE(config.FilePath, config.Force)
			if result.Applied {
				fmt.Printf("✅ %s Stripping: %s\n", fileType, result.Message)
			} else {
				fmt.Printf("❌ %s Stripping: %s\n", fileType, result.Message)
			}
		} else if isELF {
			result := elfrw.StripELFDetailed(config.FilePath, false, config.Force)
			if result.Applied {
				fmt.Printf("✅ %s Stripping: %s\n", fileType, result.Message)
			} else {
				fmt.Printf("❌ %s Stripping: %s\n", fileType, result.Message)
			}
		}
	}

	// Execute compact operation if requested
	if config.Compact {
		if isPE {
			result := perw.CompactPE(config.FilePath)
			if result.Applied {
				fmt.Printf("✅ %s Compaction: %s\n", fileType, result.Message)
			} else {
				fmt.Printf("❌ %s Compaction: %s\n", fileType, result.Message)
			}
		} else if isELF {
			result := elfrw.StripELFDetailed(config.FilePath, true, config.Force)
			if result.Applied {
				fmt.Printf("✅ %s Compaction: %s\n", fileType, result.Message)
			} else {
				fmt.Printf("❌ %s Compaction: %s\n", fileType, result.Message)
			}
		}
	}

	return nil
}

// runObfuscate performs obfuscation operations
func runObfuscate(config *Configuration, isPE, isELF bool) error {
	fmt.Println("\n=== Obfuscation Operations ===")
	if isPE {
		fmt.Println("Applying PE obfuscation techniques...")

		// PE obfuscation techniques
		techniques := []struct {
			name  string
			fn    func(string) *common.OperationResult
			risky bool
		}{
			{"Section names", perw.ObfuscateSectionNames, false},
			{"Base addresses", perw.ObfuscateBaseAddresses, true},
			{"Runtime strings", perw.ObfuscateRuntimeStrings, false},
		}

		var appliedTechniques []string
		var skippedTechniques []string
		var warningShown bool

		appliedCount := 0
		for _, tech := range techniques {
			if tech.risky && !config.Force {
				skippedTechniques = append(skippedTechniques, fmt.Sprintf("%s (risky operation)", tech.name))
				continue
			}

			result := tech.fn(config.FilePath)
			if result.Applied {
				appliedTechniques = append(appliedTechniques, fmt.Sprintf("%s: %s", tech.name, result.Message))
				appliedCount++
			} else {
				// Check if message contains "Corrupted or modified PE structure" warning
				if !warningShown && (result.Message == "Corrupted or modified PE structure (fail to read string table length: EOF)" ||
					result.Message == "fail to read string table length: EOF") {
					fmt.Println("⚠️  PE structure warning detected (packed/compressed executable)")
					warningShown = true
				}
				skippedTechniques = append(skippedTechniques, fmt.Sprintf("%s (%s)", tech.name, result.Message))
			}
		}

		// Display results in organized format
		if len(appliedTechniques) > 0 {
			fmt.Println("\n✅ Successfully Applied:")
			for _, tech := range appliedTechniques {
				fmt.Printf("  • %s\n", tech)
			}
		}

		if len(skippedTechniques) > 0 {
			fmt.Println("\n⚠️  Skipped Techniques:")
			for _, tech := range skippedTechniques {
				fmt.Printf("  • %s\n", tech)
			}
		}

		fmt.Printf("\n📊 Summary: %d/%d techniques applied successfully\n", appliedCount, len(techniques))

	} else if isELF {
		fmt.Println("Applying ELF obfuscation techniques...")

		// Check if this is a Go binary before any obfuscation
		isGoBinary, err := elfrw.IsGoBinary(config.FilePath)
		if err != nil {
			return fmt.Errorf("failed to check if Go binary: %v", err)
		}

		// ELF obfuscation techniques
		techniques := []struct {
			name      string
			fn        func(string) *common.OperationResult
			skipForGo bool
			risky     bool
		}{
			{"Section names", elfrw.ObfuscateSectionNamesDetailed, false, false},
			{"Base addresses", func(path string) *common.OperationResult {
				return elfrw.ObfuscateBaseAddressesDetailed(path, config.Force)
			}, true, true}, // Skip for Go binaries, risky
		}

		var appliedTechniques []string
		var skippedTechniques []string

		appliedCount := 0
		for _, tech := range techniques {
			if tech.skipForGo && isGoBinary && !config.Force {
				skippedTechniques = append(skippedTechniques, fmt.Sprintf("%s (Go binary - would break runtime)", tech.name))
				continue
			}
			if tech.risky && !config.Force {
				skippedTechniques = append(skippedTechniques, fmt.Sprintf("%s (risky operation)", tech.name))
				continue
			}

			result := tech.fn(config.FilePath)
			if result.Applied {
				appliedTechniques = append(appliedTechniques, fmt.Sprintf("%s: %s", tech.name, result.Message))
				appliedCount++
			} else {
				skippedTechniques = append(skippedTechniques, fmt.Sprintf("%s (%s)", tech.name, result.Message))
			}
		}

		// Apply additional obfuscation for non-Go binaries only
		if !isGoBinary || config.Force {
			result := elfrw.ObfuscateAllDetailed(config.FilePath, config.Force)
			if result.Applied {
				appliedTechniques = append(appliedTechniques, fmt.Sprintf("Additional obfuscation: %s", result.Message))
				appliedCount++
			} else {
				skippedTechniques = append(skippedTechniques, fmt.Sprintf("Additional obfuscation (%s)", result.Message))
			}
		} else {
			skippedTechniques = append(skippedTechniques, "Additional obfuscation (Go binary - would break runtime)")
		}

		// Display results in organized format
		if len(appliedTechniques) > 0 {
			fmt.Println("\n✅ Successfully Applied:")
			for _, tech := range appliedTechniques {
				fmt.Printf("  • %s\n", tech)
			}
		}

		if len(skippedTechniques) > 0 {
			fmt.Println("\n⚠️  Skipped Techniques:")
			for _, tech := range skippedTechniques {
				fmt.Printf("  • %s\n", tech)
			}
		}

		fmt.Printf("\n📊 Summary: %d ELF obfuscation techniques applied\n", appliedCount)
	}

	return nil
}

// runRegex performs regex-based stripping operations
func runRegex(config *Configuration, isPE, isELF bool) error {
	fmt.Println("\n=== Regex Operations ===")
	fmt.Printf("Applying custom regex pattern: %s\n", config.Regex)

	fileType := "ELF"
	if isPE {
		fileType = "PE"
	}

	if isPE {
		// Per PE, al momento usiamo la funzione regex generale
		result := perw.StripAllRegexRules(config.FilePath, config.Force)
		if result.Applied {
			fmt.Printf("✅ %s Regex Stripping: %s\n", fileType, result.Message)
		} else {
			fmt.Printf("❌ %s Regex Stripping: %s\n", fileType, result.Message)
		}
	} else if isELF {
		// Per ELF implementeremo la funzione custom regex in futuro
		fmt.Printf("⚠️  %s Custom Regex: not yet implemented for ELF files\n", fileType)
	}

	return nil
}

// runInsert performs section insertion operations
func runInsert(config *Configuration, isPE, isELF bool) error {
	fmt.Println("\n=== Insert Operations ===")
	fmt.Printf("Inserting section: %s\n", config.Insert)

	fileType := "ELF"
	if isPE {
		fileType = "PE"
	}

	// Parse insert specification (name:data_or_file[:password])
	parts := strings.Split(config.Insert, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid insert format, expected name:data_or_file[:password]")
	}

	sectionName := parts[0]
	dataOrFile := parts[1]
	password := ""
	if len(parts) > 2 {
		password = parts[2]
	}

	// Determine if dataOrFile is a file path or string data
	isFile := false
	if _, err := os.Stat(dataOrFile); err == nil {
		// File exists
		isFile = true
	}

	if isPE {
		var result *common.OperationResult
		if isFile {
			result = perw.AddHexSection(config.FilePath, sectionName, dataOrFile, password)
		} else {
			result = perw.AddHexSectionFromString(config.FilePath, sectionName, dataOrFile, password)
		}

		if result.Applied {
			fmt.Printf("✅ %s Section Insertion: %s\n", fileType, result.Message)
		} else {
			fmt.Printf("❌ %s Section Insertion: %s\n", fileType, result.Message)
		}
	} else if isELF {
		result := elfrw.AddHexSectionDetailed(config.FilePath, sectionName, dataOrFile, password)
		if result.Applied {
			fmt.Printf("✅ %s Section Insertion: %s\n", fileType, result.Message)
		} else {
			fmt.Printf("❌ %s Section Insertion: %s\n", fileType, result.Message)
		}
	}

	return nil
}

// runRiskyOperations applies risky stripping operations after obfuscation
// printUsage prints the help message
func printUsage() {
	fmt.Printf(`go-super-strip - Advanced Executable Stripping and Obfuscation Tool

USAGE:
	%s [OPTIONS] <file>

DESCRIPTION:
	Process PE/ELF executables with stripping, obfuscation, and analysis capabilities.
	Operations are performed in strict order: strip -> compact -> obfuscate -> regex -> insert

OPTIONS:
	-s, --strip          Strip debug and symbol sections
	-c, --compact        Apply size reduction by removing sections
	-f, --force          Apply risky operations to -s, -c, or -o
	-o, --obfuscate      Apply obfuscation techniques
	-r, --regex <pattern> Strip bytes matching a custom regex pattern
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
	%s -s program                		  	# Strip debug sections
	%s -c program              				# Compact file (remove sections)
	%s -o program              		 		# Apply obfuscation techniques
	%s -s -c -o program        		 	   	# Strip, compact, and obfuscate (full pipeline)
	%s -s -f program            		   	# Strip with risky operations (relocations, etc.)
	%s -c -f program               			# Compact with risky operations
	%s -s -r 'UPX!' program        			# Strip built-in rules, then custom regex 'UPX!'
	%s -i 'custom:data.bin' program 		# Add hex section from file
	%s -i 'custom:HelloWorld' program 		# Add hex section from string
	%s -i 'secret:data.bin:pass123' program # Add encrypted hex section

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
