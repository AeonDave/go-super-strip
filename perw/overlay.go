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
func (p *PEFile) AddOverlay(dataOrFile string, password string) error {
	fileStat, err := os.Stat(dataOrFile)
	isFile := err == nil && !fileStat.IsDir()

	var finalContent []byte
	if isFile {
		finalContent, err = common.ProcessFileForInsertion(dataOrFile, password)
		if err != nil {
			return fmt.Errorf("failed to process file for overlay: %w", err)
		}
	} else {
		finalContent, err = common.ProcessStringForInsertion(dataOrFile, password)
		if err != nil {
			return fmt.Errorf("failed to process string for overlay: %w", err)
		}
	}

	// Use the fallback method directly as we want to append data without modifying PE structure
	return p.appendDataToFileDirectly(finalContent)
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
