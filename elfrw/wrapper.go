package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
)

// AnalyzeELF analyzes an ELF file and prints detailed information
func AnalyzeELF(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return err
	}

	return elfFile.Analyze()
}

// AddHexSectionDetailed adds a hex section to an ELF file with detailed result
func AddHexSectionDetailed(filePath, sectionName, sourceFile, password string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	// Check if section with same name already exists
	for _, section := range elfFile.Sections {
		if section.Name == sectionName {
			return common.NewSkipped(fmt.Sprintf("section '%s' already exists", sectionName))
		}
	}

	// Add hex section
	if err := elfFile.AddHexSection(sectionName, sourceFile, password); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to add hex section: %v", err))
	}

	// Commit changes
	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to commit changes: %v", err))
	}

	message := fmt.Sprintf("added hex section '%s'", sectionName)
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

// OverlayELF adds data as an overlay to an ELF file without creating a named section
func OverlayELF(filePath, dataOrFile, password string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	// Add overlay
	if err := elfFile.AddOverlay(dataOrFile, password); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to add overlay: %v", err))
	}

	message := "added overlay data"
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

// ObfuscateELF performs all ELF obfuscation operations with detailed result
func ObfuscateELF(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	// Check if this is a Go binary before any obfuscation
	isGoBinary := elfFile.isGoBinary()

	// Define the techniques to apply
	techniques := []struct {
		name      string
		fn        func() *common.OperationResult
		skipForGo bool
		risky     bool
	}{
		{"Section names", elfFile.RandomizeSectionNames, false, false},
		{"Base addresses", func() *common.OperationResult { return elfFile.ObfuscateBaseAddresses(force) }, true, true},
	}

	var appliedTechniques []string
	var skippedTechniques []string

	appliedCount := 0
	for _, tech := range techniques {
		if tech.skipForGo && isGoBinary && !force {
			skippedTechniques = append(skippedTechniques, fmt.Sprintf("%s (Go binary - would break runtime)", tech.name))
			continue
		}
		if tech.risky && !force {
			skippedTechniques = append(skippedTechniques, fmt.Sprintf("%s (risky operation)", tech.name))
			continue
		}

		result := tech.fn()
		if result.Applied {
			appliedTechniques = append(appliedTechniques, fmt.Sprintf("%s: %s", tech.name, result.Message))
			appliedCount++
		} else {
			skippedTechniques = append(skippedTechniques, fmt.Sprintf("%s (%s)", tech.name, result.Message))
		}
	}

	// Apply additional obfuscation for non-Go binaries only
	if !isGoBinary || force {
		result := elfFile.ObfuscateAll(force)
		if result.Applied {
			appliedTechniques = append(appliedTechniques, fmt.Sprintf("Additional obfuscation: %s", result.Message))
			appliedCount++
		} else {
			skippedTechniques = append(skippedTechniques, fmt.Sprintf("Additional obfuscation (%s)", result.Message))
		}
	} else {
		skippedTechniques = append(skippedTechniques, "Additional obfuscation (Go binary - would break runtime)")
	}

	// Save changes if any technique was applied
	if appliedCount > 0 {
		if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
		}
	}

	// Create result message
	var message string
	if appliedCount > 0 {
		message = fmt.Sprintf("%d ELF obfuscation techniques applied", appliedCount)
	} else {
		message = "No obfuscation techniques applied"
	}

	return common.NewApplied(message, appliedCount)
}

// IsGoBinary checks if an ELF file is a Go binary without opening for write
func IsGoBinary(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return false, err
	}

	return elfFile.isGoBinary(), nil
}

// AdvancedStripELFDetailed performs comprehensive ELF stripping with optional size reduction
func AdvancedStripELFDetailed(filePath string, compact bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	result := elfFile.AdvancedStripDetailed(compact)
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

func StripELFDetailed(filePath string, compact bool, force bool) *common.OperationResult {
	// Get initial file size for compaction calculation
	initialFileInfo, err := os.Stat(filePath)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to get file size: %v", err))
	}
	initialSize := initialFileInfo.Size()

	// Check if this is a Go binary before operations
	isGoBinary, err := IsGoBinary(filePath)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to check binary type: %v", err))
	}

	if isGoBinary && !force {
		return common.NewSkipped("Go binary detected (use -f to force risky operations)")
	}

	// Use the existing AdvancedStripELFDetailed function for comprehensive stripping
	// This includes debug sections, symbol tables, and optional compaction
	result := AdvancedStripELFDetailed(filePath, compact)

	if result.Applied {
		// Calculate final file size and compaction percentage
		finalFileInfo, err := os.Stat(filePath)
		finalSize := initialSize // fallback to initial size if we can't get new size
		compressionInfo := ""

		if err == nil {
			finalSize = finalFileInfo.Size()
			if finalSize < initialSize {
				savedBytes := initialSize - finalSize
				percentage := float64(savedBytes) / float64(initialSize) * 100
				compressionInfo = fmt.Sprintf(" (%.1f%% reduction: %d → %d bytes, saved %d bytes)",
					percentage, initialSize, finalSize, savedBytes)
			} else if compact {
				compressionInfo = fmt.Sprintf(" (no size reduction: %d bytes)", finalSize)
			}
		}

		// Update result message with compaction info
		result.Message += compressionInfo

		if isGoBinary && force {
			// Add warning message for forced Go binary operations
			result.Message = fmt.Sprintf("WARNING: Go binary forced - %s", result.Message)
		}
	}

	return result
}
