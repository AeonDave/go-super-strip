package perw

import (
	"fmt"
	"gosstrip/common"
	"io"
	"os"
)

// AddOverlay adds data as an overlay to a PE file without creating a named section
// The format is similar to AddHexSection but without a section name
// dataOrFile: path to a file or a string to add
// password: optional password for encryption
func (p *PEFile) AddOverlay(dataOrFile string, password string) *common.OperationResult {
	fileStat, err := os.Stat(dataOrFile)
	isFile := err == nil && !fileStat.IsDir()

	var finalContent []byte
	if isFile {
		finalContent, err = common.ProcessFileForInsertion(dataOrFile, password)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("Failed to process file for overlay: %v", err))
		}
	} else {
		finalContent, err = common.ProcessStringForInsertion(dataOrFile, password)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("Failed to process string for overlay: %v", err))
		}
	}

	// Use the fallback method directly as we want to append data without modifying PE structure
	err = p.appendDataToFileDirectly(finalContent)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to add overlay: %v", err))
	}

	message := "Added overlay data"
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

func (p *PEFile) appendDataToFileDirectly(content []byte) error {
	if _, err := p.File.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("impossibile posizionarsi alla fine del file: %w", err)
	}
	if _, err := p.File.Write(content); err != nil {
		return fmt.Errorf("impossibile scrivere il contenuto nel file: %w", err)
	}
	return nil
}
