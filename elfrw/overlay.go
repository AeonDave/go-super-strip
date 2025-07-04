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
func (e *ELFFile) AddOverlay(dataOrFile string, password string) *common.OperationResult {
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

	// Append data directly to the file
	if _, err := e.File.Seek(0, io.SeekEnd); err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to seek to end of file: %v", err))
	}

	if _, err := e.File.Write(finalContent); err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to write overlay data: %v", err))
	}

	message := "Added overlay data"
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

func (e *ELFFile) ExtractOverlay() ([]byte, error) {
	if !e.HasOverlay {
		return nil, fmt.Errorf("no overlay found in ELF file")
	}

	if e.OverlayOffset < 0 || e.OverlayOffset >= int64(len(e.RawData)) {
		return nil, fmt.Errorf("invalid overlay offset: %d", e.OverlayOffset)
	}

	overlayEnd := e.OverlayOffset + e.OverlaySize
	if overlayEnd > int64(len(e.RawData)) {
		overlayEnd = int64(len(e.RawData))
	}

	overlayData := make([]byte, overlayEnd-e.OverlayOffset)
	copy(overlayData, e.RawData[e.OverlayOffset:overlayEnd])

	return overlayData, nil
}
