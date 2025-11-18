package perw

import (
	"fmt"
	"gosstrip/common"
	"os"
)

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

	if len(finalContent) == 0 {
		return common.NewSkipped("Overlay content is empty")
	}

	var removedOverlay int64
	if p.HasOverlay && p.OverlayOffset >= 0 && p.OverlayOffset <= int64(len(p.RawData)) {
		start := int(p.OverlayOffset)
		if start < len(p.RawData) {
			end := start + int(p.OverlaySize)
			if end > len(p.RawData) {
				end = len(p.RawData)
			}
			p.RawData = p.RawData[:start]
			removedOverlay = int64(end - start)
		}
	}

	start := len(p.RawData)
	p.RawData = append(p.RawData, finalContent...)
	p.FileSize = int64(len(p.RawData))
	p.HasOverlay = true
	p.OverlayOffset = int64(start)
	p.OverlaySize = int64(len(finalContent))

	message := "Added overlay data"
	if password != "" {
		message += " (encrypted)"
	}
	result := common.NewApplied(message, 1)
	if removedOverlay > 0 {
		result.AddDetail(fmt.Sprintf("removed existing overlay (%d bytes)", removedOverlay), int(removedOverlay), false)
	}
	result.AddDetail(fmt.Sprintf("overlay size: %d bytes", len(finalContent)), len(finalContent), false)
	return result
}
