package perw

import (
	"fmt"
	"gosstrip/common"
	"os"
	"strings"
)

func ExtractSection(filePath, name string, index *int, password string) ([]byte, string, error) {
	peFile, err := readPe(filePath, os.O_RDONLY)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = peFile.Close() }()
	return peFile.extractSectionPayload(name, index, password)
}

func (p *PEFile) extractSectionPayload(name string, index *int, password string) ([]byte, string, error) {
	section, err := p.resolveSectionForExtraction(name, index)
	if err != nil {
		return nil, "", err
	}
	if section.Offset < 0 {
		return nil, "", fmt.Errorf("section %s has invalid offset", section.Name)
	}
	maxLength := int(section.Size)
	if maxLength <= 0 {
		return nil, "", fmt.Errorf("section %s has no data on disk", section.Name)
	}
	available := len(p.RawData) - int(section.Offset)
	if maxLength > available {
		maxLength = available
	}
	payloadLen := maxLength
	if section.VirtualSize > 0 && int(section.VirtualSize) < payloadLen {
		payloadLen = int(section.VirtualSize)
	}
	raw := make([]byte, payloadLen)
	copy(raw, p.RawData[section.Offset:int(section.Offset)+payloadLen])
	data, err := common.ProcessExtractedData(raw, password)
	if err != nil {
		return nil, "", err
	}
	sectionName := strings.TrimRight(section.Name, "\x00")
	if sectionName == "" {
		sectionName = ".data"
	}
	return data, sectionName, nil
}

func (p *PEFile) resolveSectionForExtraction(name string, index *int) (*Section, error) {
	if strings.TrimSpace(name) != "" {
		target := common.SanitizeSectionName(name)
		for i := range p.Sections {
			candidate := strings.TrimRight(p.Sections[i].Name, "\x00")
			if candidate == target {
				return &p.Sections[i], nil
			}
		}
		return nil, fmt.Errorf("section %q not found", target)
	}
	if index == nil {
		return nil, fmt.Errorf("section index required when name is empty")
	}
	if *index < 0 || *index >= len(p.Sections) {
		return nil, fmt.Errorf("section index %d out of range", *index)
	}
	return &p.Sections[*index], nil
}
