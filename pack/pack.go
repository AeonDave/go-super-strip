package pack

import (
	"fmt"
	"os"

	"gosstrip/elfrw"
	"gosstrip/perw"
)

// Pack è la funzione principale per il packing
func Pack(filePath string, optionsString string, outputPath string) error {
	// 1. Parsea opzioni
	config, err := ParseOptions(optionsString)
	if err != nil {
		return fmt.Errorf("failed to parse options: %w", err)
	}

	// 2. Valida configurazione
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	if outputPath != "" {
		config.OutputPath = outputPath
	}

	if config.Verbose {
		fmt.Println(config.String())
	}

	// 3. Determina tipo di file
	isPE, isELF, err := determineFileType(filePath)
	if err != nil {
		return err
	}

	if !isPE && !isELF {
		return fmt.Errorf("unsupported file type: %s (must be ELF or PE)", filePath)
	}

	// 4. Packa il file
	var result *PackResult

	if isELF {
		fmt.Println("🔧 Packing ELF executable...")
		result, err = PackELF(filePath, config)
	} else {
		fmt.Println("🔧 Packing PE executable...")
		result, err = PackPE(filePath, config)
	}

	if err != nil {
		return fmt.Errorf("packing failed: %w", err)
	}

	// 5. Stampa risultato
	if !config.Verbose {
		fmt.Println(result.String())
	}

	return nil
}

// determineFileType determina se il file è ELF o PE
func determineFileType(filePath string) (bool, bool, error) {
	// Check se esiste
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, false, fmt.Errorf("file does not exist: %s", filePath)
	}

	// Check PE
	isPE, err := perw.IsPEFile(filePath)
	if err != nil {
		return false, false, fmt.Errorf("error checking PE file type: %v", err)
	}

	// Check ELF
	isELF := false
	if !isPE {
		isELF, err = elfrw.IsELFFile(filePath)
		if err != nil {
			return false, false, fmt.Errorf("error checking ELF file type: %v", err)
		}
	}

	return isPE, isELF, nil
}
