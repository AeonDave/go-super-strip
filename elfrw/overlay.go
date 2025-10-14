package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
)

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

	if len(finalContent) == 0 {
		return common.NewSkipped("Overlay content is empty")
	}

	overlayOffset := int64(len(e.RawData))
	e.RawData = append(e.RawData, finalContent...)
	e.HasOverlay = true
	e.OverlayOffset = overlayOffset
	e.OverlaySize = int64(len(finalContent))

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
