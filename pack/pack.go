package pack

import (
	"fmt"
	"os"

	"gosstrip/elfrw"
	"gosstrip/perw"
)

// Pack è la funzione principale per il packing basata su stringhe di configurazione.
func Pack(filePath string, optionsString string, outputPath string) error {
	config, err := ParseOptions(optionsString)
	if err != nil {
		return fmt.Errorf("failed to parse options: %w", err)
	}
	return runPackWithConfig(filePath, config, outputPath)
}

// PackWithConfig consente di riutilizzare una configurazione già parseata.
func PackWithConfig(filePath string, config *PackConfig, outputPath string) error {
	if config == nil {
		return fmt.Errorf("pack configuration cannot be nil")
	}
	return runPackWithConfig(filePath, config, outputPath)
}

func runPackWithConfig(filePath string, config *PackConfig, outputPath string) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	if outputPath != "" {
		config.OutputPath = outputPath
	}

	if config.Verbose {
		fmt.Println(config.String())
	}

	isPE, isELF, err := determineFileType(filePath)
	if err != nil {
		return err
	}

	if !isPE && !isELF {
		return fmt.Errorf("unsupported file type: %s (must be ELF or PE)", filePath)
	}

	var result *PackResult

	if isELF {
		fmt.Println("?? Packing ELF executable...")
		result, err = PackELF(filePath, config)
	} else {
		fmt.Println("?? Packing PE executable...")
		result, err = PackPE(filePath, config)
	}

	if err != nil {
		return fmt.Errorf("packing failed: %w", err)
	}

	if !config.Verbose {
		fmt.Println(result.String())
	}

	return nil
}

// determineFileType determina se il file è ELF o PE.
func determineFileType(filePath string) (bool, bool, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, false, fmt.Errorf("file does not exist: %s", filePath)
	}

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

	return isPE, isELF, nil
}
