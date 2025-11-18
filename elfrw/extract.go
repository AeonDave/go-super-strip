package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
	"strings"
)

func ExtractSection(filePath, name string, index *int, password string) ([]byte, string, error) {
	elfFile, err := readElf(filePath, os.O_RDONLY)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = elfFile.Close() }()
	return elfFile.extractSectionPayload(name, index, password)
}

func (e *ELFFile) extractSectionPayload(name string, index *int, password string) ([]byte, string, error) {
	section, err := e.resolveSectionForExtraction(name, index)
	if err != nil {
		return nil, "", err
	}
	if section.Offset < 0 || section.Size <= 0 {
		return nil, "", fmt.Errorf("section %s has no data on disk", section.Name)
	}
	if section.Offset+section.Size > int64(len(e.RawData)) {
		return nil, "", fmt.Errorf("section %s exceeds file bounds", section.Name)
	}
	raw := make([]byte, section.Size)
	copy(raw, e.RawData[section.Offset:section.Offset+section.Size])
	data, err := common.ProcessExtractedData(raw, password)
	if err != nil {
		return nil, "", err
	}
	return data, section.Name, nil
}

func (e *ELFFile) resolveSectionForExtraction(name string, index *int) (*Section, error) {
	if strings.TrimSpace(name) != "" {
		target := name
		for i := range e.Sections {
			if e.Sections[i].Name == target {
				return &e.Sections[i], nil
			}
		}
		return nil, fmt.Errorf("section %q not found", target)
	}
	if index == nil {
		return nil, fmt.Errorf("section index required when name is empty")
	}
	if *index < 0 || *index >= len(e.Sections) {
		return nil, fmt.Errorf("section index %d out of range", *index)
	}
	return &e.Sections[*index], nil
}
