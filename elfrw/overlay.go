package elfrw

import (
	"fmt"
	"gosstrip/common"
	"io"
	"os"
)

// AddOverlay adds data as an overlay to an ELF file without creating a named section
// dataOrFile: path to a file or a string to add
// password: optional password for encryption
func (e *ELFFile) AddOverlay(dataOrFile string, password string) error {
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

	// Append data directly to the file
	if _, err := e.File.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("failed to seek to end of file: %w", err)
	}

	if _, err := e.File.Write(finalContent); err != nil {
		return fmt.Errorf("failed to write overlay data: %w", err)
	}

	return nil
}
