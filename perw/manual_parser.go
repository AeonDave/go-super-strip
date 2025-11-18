package perw

import (
	"bytes"
	"fmt"
	"gosstrip/common"
	"strings"
	"time"
)

func (p *PEFile) parseBasicSectionsFromRaw() error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small to be a valid PE")
	}

	peOffset := int(p.RawData[60]) | int(p.RawData[61])<<8 | int(p.RawData[62])<<16 | int(p.RawData[63])<<24
	if peOffset+24 >= len(p.RawData) {
		return fmt.Errorf("invalid PE header offset")
	}

	if string(p.RawData[peOffset:peOffset+4]) != "PE\x00\x00" {
		return fmt.Errorf("invalid PE signature")
	}

	numSections := int(p.RawData[peOffset+6]) | int(p.RawData[peOffset+7])<<8
	optHeaderSize := int(p.RawData[peOffset+20]) | int(p.RawData[peOffset+21])<<8
	sectionHeadersOffset := peOffset + 24 + optHeaderSize
	if sectionHeadersOffset+numSections*40 > len(p.RawData) {
		return fmt.Errorf("section headers extend beyond file")
	}

	validSections := 0
	for i := 0; i < numSections; i++ {
		offset := sectionHeadersOffset + i*40
		if offset+40 > len(p.RawData) {
			fmt.Printf("⚠️  Section %d header extends beyond file, stopping\n", i)
			break
		}

		nameBytes := p.RawData[offset : offset+8]
		name := p.sanitizeSectionName(nameBytes)

		virtualSize := uint32(p.RawData[offset+8]) | uint32(p.RawData[offset+9])<<8 |
			uint32(p.RawData[offset+10])<<16 | uint32(p.RawData[offset+11])<<24
		virtualAddress := uint32(p.RawData[offset+12]) | uint32(p.RawData[offset+13])<<8 |
			uint32(p.RawData[offset+14])<<16 | uint32(p.RawData[offset+15])<<24
		sizeOfRawData := int64(p.RawData[offset+16]) | int64(p.RawData[offset+17])<<8 |
			int64(p.RawData[offset+18])<<16 | int64(p.RawData[offset+19])<<24
		pointerToRawData := int64(p.RawData[offset+20]) | int64(p.RawData[offset+21])<<8 |
			int64(p.RawData[offset+22])<<16 | int64(p.RawData[offset+23])<<24
		characteristics := uint32(p.RawData[offset+36]) | uint32(p.RawData[offset+37])<<8 |
			uint32(p.RawData[offset+38])<<16 | uint32(p.RawData[offset+39])<<24

		if p.isValidSectionData(virtualAddress, virtualSize, pointerToRawData, sizeOfRawData) {
			section := Section{
				Name:           name,
				VirtualAddress: virtualAddress,
				VirtualSize:    virtualSize,
				Size:           sizeOfRawData,
				Offset:         pointerToRawData,
				FileOffset:     uint32(pointerToRawData),
				Flags:          characteristics,
				Index:          validSections,
				CommonSectionInfo: common.CommonSectionInfo{
					IsExecutable: (characteristics & 0x20000000) != 0,
					IsReadable:   (characteristics & 0x40000000) != 0,
					IsWritable:   (characteristics & 0x80000000) != 0,
				},
			}

			p.fillSectionHashesAndEntropy(&section)
			p.Sections = append(p.Sections, section)
			validSections++
		}
	}

	if validSections < numSections {
		fmt.Printf("⚠️  Enhanced parser successfully processed %d/%d sections\n", validSections, numSections)
	}

	return nil
}

func (p *PEFile) parseBasicHeadersFromRaw() error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small for PE headers")
	}

	peOffset := int(p.RawData[60]) | int(p.RawData[61])<<8 | int(p.RawData[62])<<16 | int(p.RawData[63])<<24
	if peOffset+24 >= len(p.RawData) {
		return fmt.Errorf("invalid PE header offset")
	}

	if string(p.RawData[peOffset:peOffset+4]) != "PE\x00\x00" {
		return fmt.Errorf("invalid PE signature")
	}

	machine := uint16(p.RawData[peOffset+4]) | uint16(p.RawData[peOffset+5])<<8
	timestamp := uint32(p.RawData[peOffset+8]) | uint32(p.RawData[peOffset+9])<<8 |
		uint32(p.RawData[peOffset+10])<<16 | uint32(p.RawData[peOffset+11])<<24
	optHeaderSize := uint16(p.RawData[peOffset+20]) | uint16(p.RawData[peOffset+21])<<8
	optHeaderOffset := peOffset + 24
	if optHeaderOffset+28 <= len(p.RawData) && optHeaderSize >= 28 {
		magic := uint16(p.RawData[optHeaderOffset]) | uint16(p.RawData[optHeaderOffset+1])<<8
		switch magic {
		case 0x10b:
			if optHeaderOffset+96 <= len(p.RawData) {
				p.entryPoint = uint32(p.RawData[optHeaderOffset+16]) | uint32(p.RawData[optHeaderOffset+17])<<8 |
					uint32(p.RawData[optHeaderOffset+18])<<16 | uint32(p.RawData[optHeaderOffset+19])<<24
				p.imageBase = uint64(uint32(p.RawData[optHeaderOffset+28]) | uint32(p.RawData[optHeaderOffset+29])<<8 |
					uint32(p.RawData[optHeaderOffset+30])<<16 | uint32(p.RawData[optHeaderOffset+31])<<24)
				p.sizeOfImage = uint32(p.RawData[optHeaderOffset+56]) | uint32(p.RawData[optHeaderOffset+57])<<8 |
					uint32(p.RawData[optHeaderOffset+58])<<16 | uint32(p.RawData[optHeaderOffset+59])<<24
				p.sizeOfHeaders = uint32(p.RawData[optHeaderOffset+60]) | uint32(p.RawData[optHeaderOffset+61])<<8 |
					uint32(p.RawData[optHeaderOffset+62])<<16 | uint32(p.RawData[optHeaderOffset+63])<<24
				p.checksum = uint32(p.RawData[optHeaderOffset+64]) | uint32(p.RawData[optHeaderOffset+65])<<8 |
					uint32(p.RawData[optHeaderOffset+66])<<16 | uint32(p.RawData[optHeaderOffset+67])<<24
				p.subsystem = uint16(p.RawData[optHeaderOffset+68]) | uint16(p.RawData[optHeaderOffset+69])<<8
				p.dllCharacteristics = uint16(p.RawData[optHeaderOffset+70]) | uint16(p.RawData[optHeaderOffset+71])<<8
			}
		case 0x20b:
			if optHeaderOffset+112 <= len(p.RawData) {
				p.entryPoint = uint32(p.RawData[optHeaderOffset+16]) | uint32(p.RawData[optHeaderOffset+17])<<8 |
					uint32(p.RawData[optHeaderOffset+18])<<16 | uint32(p.RawData[optHeaderOffset+19])<<24
				p.imageBase = uint64(p.RawData[optHeaderOffset+24]) | uint64(p.RawData[optHeaderOffset+25])<<8 |
					uint64(p.RawData[optHeaderOffset+26])<<16 | uint64(p.RawData[optHeaderOffset+27])<<24 |
					uint64(p.RawData[optHeaderOffset+28])<<32 | uint64(p.RawData[optHeaderOffset+29])<<40 |
					uint64(p.RawData[optHeaderOffset+30])<<48 | uint64(p.RawData[optHeaderOffset+31])<<56
				p.sizeOfImage = uint32(p.RawData[optHeaderOffset+56]) | uint32(p.RawData[optHeaderOffset+57])<<8 |
					uint32(p.RawData[optHeaderOffset+58])<<16 | uint32(p.RawData[optHeaderOffset+59])<<24
				p.sizeOfHeaders = uint32(p.RawData[optHeaderOffset+60]) | uint32(p.RawData[optHeaderOffset+61])<<8 |
					uint32(p.RawData[optHeaderOffset+62])<<16 | uint32(p.RawData[optHeaderOffset+63])<<24
				p.checksum = uint32(p.RawData[optHeaderOffset+64]) | uint32(p.RawData[optHeaderOffset+65])<<8 |
					uint32(p.RawData[optHeaderOffset+66])<<16 | uint32(p.RawData[optHeaderOffset+67])<<24
				p.subsystem = uint16(p.RawData[optHeaderOffset+68]) | uint16(p.RawData[optHeaderOffset+69])<<8
				p.dllCharacteristics = uint16(p.RawData[optHeaderOffset+70]) | uint16(p.RawData[optHeaderOffset+71])<<8
			}
		}
	}

	switch machine {
	case 0x014c:
		p.Machine = "i386"
	case 0x8664:
		p.Machine = "amd64"
	case 0x01c0:
		p.Machine = "arm"
	case 0xaa64:
		p.Machine = "arm64"
	default:
		p.Machine = fmt.Sprintf("unknown(0x%x)", machine)
	}

	if timestamp > 0 {
		p.TimeDateStamp = time.Unix(int64(timestamp), 0).UTC().Format("2006-01-02 15:04:05 MST")
	} else {
		p.TimeDateStamp = "unknown"
	}

	return nil
}

func (p *PEFile) sanitizeSectionName(nameBytes []byte) string {
	nameBytes = bytes.TrimRight(nameBytes, "\x00")
	name := string(nameBytes)

	isValid := true
	for _, b := range nameBytes {
		if b < 32 || b > 126 {
			isValid = false
			break
		}
	}

	if !isValid || len(name) == 0 {
		return fmt.Sprintf("<stripped_%d>", len(p.Sections))
	}

	if strings.HasPrefix(name, "/") && len(name) <= 3 {
		return fmt.Sprintf("<coff_ref_%s>", strings.TrimPrefix(name, "/"))
	}

	if len(name) == 1 && (name[0] < 'A' || name[0] > 'z') {
		return fmt.Sprintf("<corrupted_%02x>", name[0])
	}

	nonPrintableCount := 0
	for _, b := range nameBytes {
		if b != 0 && (b < 32 || b > 126) {
			nonPrintableCount++
		}
	}

	if nonPrintableCount > len(nameBytes)/2 {
		return fmt.Sprintf("<mangled_%d>", len(p.Sections))
	}

	return name
}

func (p *PEFile) isValidSectionData(virtualAddr uint32, virtualSize uint32, rawDataPtr int64, rawDataSize int64) bool {
	if rawDataPtr < 0 || rawDataSize < 0 {
		return false
	}
	if rawDataPtr+rawDataSize > int64(len(p.RawData)) {
		return false
	}
	if virtualSize == 0 || virtualAddr == 0 {
		return false
	}
	return rawDataSize > 0
}

func isLikelyPacked(sections []Section) bool {
	if len(sections) == 0 {
		return false
	}
	var (
		highEntropyCount int
		total            int
		sumEntropy       float64
	)
	for _, s := range sections {
		if s.Size == 0 {
			continue
		}
		total++
		sumEntropy += s.Entropy
		if s.Entropy > 7.0 {
			highEntropyCount++
		}
	}
	if total == 0 {
		return false
	}
	avgEntropy := sumEntropy / float64(total)
	percentHigh := float64(highEntropyCount) / float64(total)

	return percentHigh > 0.5 || avgEntropy > 6.8
}
