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

	// Operation flags
	Strip     bool   // -s/--strip: Strip debug/symbol sections
	Obfuscate bool   // -o/--obfuscate: Apply obfuscation techniques
	Regex     string // -r/--regex: Strip bytes matching regex pattern
	Analyze   bool   // -a/--analyze: Analyze file structure only
	Insert    string // -i/--insert: Add section (format: name:filepath)
	Compact   bool   // -c/--compact: Apply full stripping + file size reduction via section removal
	Force     bool   // -f/--force: Apply risky operations (exception handling, etc.)
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
	insertFlag      = flag.String("i", "", "Add hex section (format: name:filepath or name:filepath:password)")
	insertFlagLong  = flag.String("insert", "", "Add hex section (format: name:filepath or name:filepath:password)")

	compactFlag     = flag.Bool("c", false, "Apply full stripping + file size reduction by removing sections")
	compactFlagLong = flag.Bool("compact", false, "Apply full stripping + file size reduction by removing sections")

	forceFlag     = flag.Bool("f", false, "Apply risky operations (exception handling, etc.)")
	forceFlagLong = flag.Bool("force", false, "Apply risky operations (exception handling, etc.)")

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
		Compact:   *compactFlag || *compactFlagLong,
		Force:     *forceFlag || *forceFlagLong,
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
		if config.Strip || config.Obfuscate || config.Regex != "" || config.Insert != "" || config.Compact || config.Force {
			fmt.Println("Note: -a/--analyze specified, ignoring other operation flags")
		}
		return config, nil
	}

	// Validate compact constraint: -c can only be used with -s
	if config.Compact && !config.Strip {
		return nil, fmt.Errorf("compact (-c) can only be used together with strip (-s)")
	}

	// Validate force constraint: -f can only be used with -s, -c, or -o
	if config.Force && !config.Strip && !config.Compact && !config.Obfuscate {
		return nil, fmt.Errorf("force (-f) can only be used with strip (-s), compact (-c), or obfuscate (-o)")
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
	} // Execute operations in strict order according to constraints:
	// 1. Strip (always first if present)
	// 2. Compact (only after strip, if both are present)
	// 3. Obfuscate (after strip/compact)
	// 4. Regex (after obfuscate)
	// 5. Insert (always last)
	var operations []string

	// 1. Strip operations (may include compact if both flags are set)
	if config.Strip {
		if err := runUnifiedStripping(config, isPE, isELF); err != nil {
			return fmt.Errorf("stripping operation failed: %v", err)
		}
		if config.Compact {
			operations = append(operations, "strip+compact")
		} else {
			operations = append(operations, "strip")
		}
	}

	// 2. Obfuscate operations (after strip/compact to work on clean structure)
	if config.Obfuscate {
		if err := runObfuscate(config, isPE, isELF); err != nil {
			return fmt.Errorf("obfuscate operation failed: %v", err)
		}
		operations = append(operations, "obfuscate")
	}

	// 2.5. Apply deferred risky operations (if obfuscation was done with force)
	if config.Force && config.Obfuscate && config.Strip {
		if err := runRiskyOperations(config, isPE, isELF); err != nil {
			return fmt.Errorf("risky operations failed: %v", err)
		}
		operations = append(operations, "risky-post-obfuscation")
	}

	// 3. Regex operations (pattern-based removal after structure changes)
	if config.Regex != "" {
		if err := runRegex(config, isPE, isELF); err != nil {
			return fmt.Errorf("regex operation failed: %v", err)
		}
		operations = append(operations, "regex")
	}

	// 4. Insert operations (always last - add new data)
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

// runUnifiedStripping performs unified stripping operations following constraints
func runUnifiedStripping(config *Configuration, isPE, isELF bool) error {
	if config.Strip && config.Compact {
		fmt.Println("=== Strip + Compact Operations ===")
		fmt.Println("Performing comprehensive stripping with compaction...")
	} else if config.Strip {
		fmt.Println("=== Strip Operations ===")
		fmt.Println("Performing comprehensive stripping...")
	}

	// Note: compact can only happen if strip is also true (validated earlier)
	compact := config.Compact
	fileType := "ELF"
	if isPE {
		fileType = "PE"
	}

	fmt.Printf("\nProcessing %s file...\n", fileType)
	// When obfuscation is enabled with force, defer risky operations until after obfuscation
	forceForStripping := config.Force
	obfuscationEnabled := config.Obfuscate

	if config.Force && config.Obfuscate {
		fmt.Println("⚠️  Using obfuscation-aware stripping: preserving sections needed for obfuscation...")
		forceForStripping = false
	}

	if isPE {
		var result *common.OperationResult
		if obfuscationEnabled {
			result = perw.StripPEDetailedWithObfuscation(config.FilePath, compact, forceForStripping, obfuscationEnabled)
		} else {
			result = perw.StripPEDetailed(config.FilePath, compact, forceForStripping)
		}

		if result.Applied {
			fmt.Printf("\n✅ %s Stripping Results:\n%s\n", fileType, result.Message)
		} else {
			fmt.Printf("\n❌ %s Stripping: %s\n", fileType, result.Message)
		}
	} else if isELF {
		// For ELF, we use the existing function (could be enhanced later)
		result := elfrw.StripELFDetailed(config.FilePath, compact, forceForStripping)
		if result.Applied {
			fmt.Printf("\n✅ %s Stripping Results:\n%s\n", fileType, result.Message)
		} else {
			fmt.Printf("\n❌ %s Stripping: %s\n", fileType, result.Message)
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
			{"Section names", perw.ObfuscateSectionNamesDetailed, false},
			{"Base addresses", func(path string) *common.OperationResult {
				return perw.ObfuscateBaseAddressesDetailed(path, config.Force)
			}, true},
			{"Load configuration", perw.ObfuscateLoadConfigurationDetailed, false},
			{"Import table", func(path string) *common.OperationResult {
				return perw.ObfuscateImportTableDetailed(path, config.Force)
			}, true},
			{"Import names", perw.ObfuscateImportNamesDetailed, false},
			{"Resource directory", perw.ObfuscateResourceDirectoryDetailed, false},
			{"Export table", func(path string) *common.OperationResult {
				return perw.ObfuscateExportTableDetailed(path, config.Force)
			}, true},
			{"Runtime strings", perw.ObfuscateRuntimeStringsDetailed, false},
		}

		appliedCount := 0
		for _, tech := range techniques {
			if tech.risky && !config.Force {
				fmt.Printf("  ⚠️  %s: SKIPPED (risky operation, use -f to force)\n", tech.name)
				continue
			}

			result := tech.fn(config.FilePath)
			if result.Applied {
				fmt.Printf("  ✓ %s: %s\n", tech.name, result.Message)
				appliedCount++
			} else {
				fmt.Printf("  ⚠️  %s: %s\n", tech.name, result.Message)
			}
		}

		fmt.Printf("\n✅ Applied %d/%d obfuscation techniques\n", appliedCount, len(techniques))

		// Apply post-obfuscation cleanup if force was deferred during stripping
		if config.Force && config.Strip {
			fmt.Println("\n🧹 Post-obfuscation cleanup:")
			fmt.Println("Removing sections that were preserved for obfuscation...")

			result := perw.StripPostObfuscationSections(config.FilePath, config.Force)
			if result.Applied {
				fmt.Printf("✅ %s\n", result.Message)
			} else {
				fmt.Printf("⚠️  %s\n", result.Message)
			}
		}

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

		appliedCount := 0
		for _, tech := range techniques {
			if tech.skipForGo && isGoBinary && !config.Force {
				fmt.Printf("  ⚠️  %s: SKIPPED (Go binary - would break runtime, use -f to force)\n", tech.name)
				continue
			}
			if tech.risky && !config.Force {
				fmt.Printf("  ⚠️  %s: SKIPPED (risky operation, use -f to force)\n", tech.name)
				continue
			}

			result := tech.fn(config.FilePath)
			if result.Applied {
				fmt.Printf("  ✓ %s: %s\n", tech.name, result.Message)
				appliedCount++
			} else {
				fmt.Printf("  ⚠️  %s: %s\n", tech.name, result.Message)
			}
		}

		// Apply additional obfuscation for non-Go binaries only
		if !isGoBinary || config.Force {
			result := elfrw.ObfuscateAllDetailed(config.FilePath, config.Force)
			if result.Applied {
				fmt.Printf("  ✓ Additional obfuscation: %s\n", result.Message)
				appliedCount++
			} else {
				fmt.Printf("  ⚠️  Additional obfuscation: %s\n", result.Message)
			}
		} else {
			fmt.Printf("  ⚠️  Additional obfuscation: SKIPPED (Go binary - would break runtime, use -f to force)\n")
		}

		fmt.Printf("\n✅ Applied %d ELF obfuscation techniques\n", appliedCount)
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

	// Parse section specification: name:filepath[:password]
	parts := strings.SplitN(config.Insert, ":", 3)
	if len(parts) < 2 || len(parts) > 3 {
		return fmt.Errorf("invalid section format, expected 'name:filepath' or 'name:filepath:password'")
	}

	sectionName := parts[0]
	sourceFile := parts[1]
	var password string
	hasPassword := len(parts) == 3
	if hasPassword {
		password = parts[2]
	}

	// Validate source file exists
	if _, err := os.Stat(sourceFile); os.IsNotExist(err) {
		return fmt.Errorf("source file does not exist: %s", sourceFile)
	}

	if hasPassword {
		fmt.Printf("Adding encrypted hexadecimal section '%s' from file: %s\n", sectionName, sourceFile)
	} else {
		fmt.Printf("Adding hexadecimal section '%s' from file: %s\n", sectionName, sourceFile)
	}

	if isPE {
		if err := perw.AddHexSection(config.FilePath, sectionName, sourceFile, password); err != nil {
			fmt.Printf("Add hex section: SKIPPED (%v)\n", err)
		} else {
			fmt.Println("Add hex section: APPLIED")
		}
	} else if isELF {
		if err := elfrw.AddHexSection(config.FilePath, sectionName, sourceFile, password); err != nil {
			fmt.Printf("Add hex section: SKIPPED (%v)\n", err)
		} else {
			fmt.Println("Add hex section: APPLIED")
		}
	}
	return nil
}

// runRiskyOperations applies risky stripping operations after obfuscation
func runRiskyOperations(config *Configuration, isPE, isELF bool) error {
	fmt.Println("\n=== Risky Operations (Post-Obfuscation) ===")
	fmt.Println("Applying deferred risky operations...")

	fileType := "ELF"
	if isPE {
		fileType = "PE"
	}

	fmt.Printf("\nProcessing %s file for risky operations...\n", fileType)

	if isPE {
		result := perw.ApplyRiskyOperationsDetailed(config.FilePath)
		if result.Applied {
			fmt.Printf("\n✅ %s Risky Operations Results:\n%s\n", fileType, result.Message)
		} else {
			fmt.Printf("\n❌ %s Risky Operations: %s\n", fileType, result.Message)
		}
	} else if isELF {
		result := elfrw.ApplyRiskyOperationsDetailed(config.FilePath)
		if result.Applied {
			fmt.Printf("\n✅ %s Risky Operations Results:\n%s\n", fileType, result.Message)
		} else {
			fmt.Printf("\n❌ %s Risky Operations: %s\n", fileType, result.Message)
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
    Operations are performed in strict order: strip → compact → obfuscate → regex → insert

OPTIONS:
    -s, --strip          Strip debug and symbol sections (comprehensive stripping)
    -c, --compact        Apply size reduction by removing sections (requires -s)
    -f, --force          Apply risky operations (only with -s, -c, or -o)
    -o, --obfuscate      Apply obfuscation techniques (section names, metadata, etc.)
    -r, --regex <pattern> Strip bytes matching regex pattern (applied after obfuscation)
    -a, --analyze        Analyze executable file structure and exit (cannot combine with other flags)
    -i, --insert <spec>  Add hex section (format: name:filepath[:password], always performed last)
    
    -v                   Enable verbose output
    -h                   Show this help

CONSTRAINT RULES:
    - -c (compact) can only be used together with -s (strip)
    - -f (force) can only be used with -s, -c, or -o
    - -a (analyze) cannot be combined with any other operation flags
    - Operations execute in fixed order regardless of flag order

EXAMPLES:
    %s -a program                    	# Analyze PE file structure
    %s -s program                    	# Strip debug sections
    %s -s -c program                 	# Strip + compact (recommended for size reduction)
    %s -o program                   	# Apply obfuscation techniques  
    %s -s -c -o program             	# Strip, compact, and obfuscate (full pipeline)
    %s -s -f program                	# Strip with risky operations (relocations, etc.)
    %s -r "golang.*" program        	# Strip bytes matching regex
    %s -i "custom:data.bin" program      	# Add hex section
    %s -s -c -o -r "debug.*" -i "data:payload.bin:secret" prog # Complete pipeline

SUPPORTED FILES:
    - PE files (.exe, .dll)
    - ELF files (Linux/Unix executables)

NOTE:
    - Each operation reports if it was applied or skipped (with reason)
    - Use -a alone for analysis without modification
    - Operations are performed in fixed order for predictable results
    - Insert operations are always performed last
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
