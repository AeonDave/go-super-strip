package perw

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"regexp"
)

// ObfuscateBaseAddresses modifies base virtual addresses with a random offset.
func (p *PEFile) ObfuscateBaseAddresses() error {
	randomOffset := uint64(rand.Intn(0x10)) * 0x10000
	if len(p.RawData) < 0x40 {
		return fmt.Errorf("file too small for DOS header")
	}
	e_lfanew := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	optHeaderOffset := e_lfanew + 24
	if !p.Is64Bit {
		optHeaderOffset += 4
	}
	imageBaseOffset := optHeaderOffset + map[bool]int64{true: 24, false: 28}[p.Is64Bit]
	if int(imageBaseOffset+int64(map[bool]int{true: 8, false: 4}[p.Is64Bit])) > len(p.RawData) {
		return fmt.Errorf("file too small for ImageBase")
	}
	if p.Is64Bit {
		current := binary.LittleEndian.Uint64(p.RawData[imageBaseOffset:])
		return WriteAtOffset(p.RawData, imageBaseOffset, current+randomOffset)
	}
	current := binary.LittleEndian.Uint32(p.RawData[imageBaseOffset:])
	return WriteAtOffset(p.RawData, imageBaseOffset, current+uint32(randomOffset))
}

// ObfuscateDirectory clears a specific directory entry in the optional header.
func (p *PEFile) ObfuscateDirectory(offset int64) error {
	if len(p.RawData) < 0x40 {
		return fmt.Errorf("file too small for DOS header")
	}
	e_lfanew := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	dirOffset := e_lfanew + 4 + 20 + offset
	if int(dirOffset+8) > len(p.RawData) {
		return fmt.Errorf("file too small for directory")
	}
	if err := WriteAtOffset(p.RawData, dirOffset, uint32(0)); err != nil {
		return err
	}
	return WriteAtOffset(p.RawData, dirOffset+4, uint32(0))
}

// ObfuscateDebugDirectory clears the debug directory.
func (p *PEFile) ObfuscateDebugDirectory() error {
	return p.ObfuscateDirectory(map[bool]int64{true: 128, false: 112}[p.Is64Bit])
}

// ObfuscateLoadConfig clears the load configuration directory.
func (p *PEFile) ObfuscateLoadConfig() error {
	return p.ObfuscateDirectory(map[bool]int64{true: 152, false: 136}[p.Is64Bit])
}

// ObfuscateTLSDirectory clears the TLS directory.
func (p *PEFile) ObfuscateTLSDirectory() error {
	return p.ObfuscateDirectory(map[bool]int64{true: 144, false: 128}[p.Is64Bit])
}

// ObfuscateSection finds and processes a section by name.
func (p *PEFile) ObfuscateSection(name string) (*Section, error) {
	for i := range p.Sections {
		if p.Sections[i].Name == name {
			return &p.Sections[i], nil
		}
	}
	return nil, nil
}

// ObfuscateSectionPadding randomizes unused bytes between PE sections.
func (p *PEFile) ObfuscateSectionPadding() {
	for i := 0; i < len(p.Sections)-1; i++ {
		end := p.Sections[i].Offset + p.Sections[i].Size
		next := p.Sections[i+1].Offset
		if end < next && next-end < 0x10000 && end > 0 {
			for j := end; j < next; j++ {
				p.RawData[j] = byte(rand.Intn(256))
			}
		}
	}
}

// ObfuscateReservedHeaderFields randomizes reserved/zero fields in PE headers.
func (p *PEFile) ObfuscateReservedHeaderFields() {
	if len(p.RawData) < 0x40 {
		return
	}
	// DOS header reserved fields (offsets 0x1C-0x3B)
	for i := 0x1C; i < 0x3C; i++ {
		p.RawData[i] = byte(rand.Intn(256))
	}
	// PE optional header reserved fields (offsets depend on arch)
	e_lfanew := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	optHeaderOffset := e_lfanew + 4 + 20
	if p.Is64Bit {
		for i := 108; i < 112; i++ { // Win64: LoaderFlags
			p.RawData[optHeaderOffset+int64(i)] = byte(rand.Intn(256))
		}
	} else {
		for i := 92; i < 96; i++ { // Win32: LoaderFlags
			p.RawData[optHeaderOffset+int64(i)] = byte(rand.Intn(256))
		}
	}
}

// ObfuscateSecondaryTimestamps randomizes non-critical timestamps in debug/resource/version sections.
func (p *PEFile) ObfuscateSecondaryTimestamps() {
	// Cerca stringhe tipo "20xx" o "19xx" in .rsrc/.data/.rdata
	pattern := regexp.MustCompile(`(?m)19\\d{2}|20\\d{2}`)
	for _, section := range p.Sections {
		if section.Name == ".rsrc" || section.Name == ".data" || section.Name == ".rdata" {
			data, err := p.ReadBytes(section.Offset, int(section.Size))
			if err == nil && len(data) >= 4 {
				indices := pattern.FindAllIndex(data, -1)
				for _, idx := range indices {
					for i := idx[0]; i < idx[1]; i++ {
						data[i] = byte(rand.Intn(10) + '0')
					}
				}
				copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
			}
		}
	}
}

// ObfuscateAll applies all obfuscation techniques.
func (p *PEFile) ObfuscateAll() error {
	if err := p.ModifyPEHeader(); err != nil {
		return fmt.Errorf("error modifying PE header: %w", err)
	}
	if err := p.RandomizeSectionNames(); err != nil {
		return fmt.Errorf("error randomizing section names: %w", err)
	}
	if err := p.ObfuscateDebugDirectory(); err != nil {
		return fmt.Errorf("error obfuscating debug directory: %w", err)
	}
	if err := p.ObfuscateLoadConfig(); err != nil {
		return fmt.Errorf("error obfuscating load config: %w", err)
	}
	if err := p.ObfuscateTLSDirectory(); err != nil {
		return fmt.Errorf("error obfuscating TLS directory: %w", err)
	}
	p.ObfuscateSectionPadding()
	p.ObfuscateReservedHeaderFields()
	p.ObfuscateSecondaryTimestamps()
	return nil
}
