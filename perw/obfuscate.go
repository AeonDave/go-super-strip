package perw

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"regexp"
)

// ObfuscateBaseAddresses modifies base virtual addresses with a random offset.
func (p *PEFile) ObfuscateBaseAddresses() error {
	randBytes := make([]byte, 4)
	_, err := rand.Read(randBytes)
	if err != nil {
		return fmt.Errorf("failed to generate random bytes for base address offset: %w", err)
	}
	// Generate a page-aligned offset, e.g., up to 255 * 0x10000 = 0xFF0000 (approx 16MB)
	// Use a smaller range to reduce likelihood of extreme values.
	randomOffset := uint64(randBytes[0]) * 0x10000 // Example: up to 255 * 64KB

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
func (p *PEFile) ObfuscateSectionPadding() error {
	for i := 0; i < len(p.Sections)-1; i++ {
		end := p.Sections[i].Offset + p.Sections[i].Size
		next := p.Sections[i+1].Offset
		if end < next && next-end < 0x10000 && end > 0 {
			paddingSize := int(next - end)
			if paddingSize <= 0 {
				continue
			}
			randomPadding := make([]byte, paddingSize)
			_, err := rand.Read(randomPadding)
			if err != nil {
				// Non-critical, can log or skip. Returning error for consistency.
				return fmt.Errorf("failed to generate random padding for section %d: %w", i, err)
			}
			copy(p.RawData[end:next], randomPadding)
		}
	}
	return nil
}

// ObfuscateReservedHeaderFields randomizes reserved/zero fields in PE headers.
func (p *PEFile) ObfuscateReservedHeaderFields() error {
	if len(p.RawData) < 0x40 {
		return fmt.Errorf("file too small for DOS header, cannot obfuscate reserved fields")
	}
	// DOS header reserved fields (offsets 0x1C-0x3B)
	dosReservedSize := 0x3C - 0x1C
	randDOSBytes := make([]byte, dosReservedSize)
	_, err := rand.Read(randDOSBytes)
	if err != nil {
		return fmt.Errorf("failed to generate random bytes for DOS reserved fields: %w", err)
	}
	copy(p.RawData[0x1C:0x3C], randDOSBytes)

	// PE optional header reserved fields (offsets depend on arch)
	eLfanewOffset := int64(0x3C)
	if eLfanewOffset+4 > int64(len(p.RawData)) {
		return fmt.Errorf("file too small to read e_lfanew for PE reserved fields")
	}
	e_lfanew := int64(binary.LittleEndian.Uint32(p.RawData[eLfanewOffset : eLfanewOffset+4]))
	optHeaderOffset := e_lfanew + 4 + 20 // PE Sig + COFF Header

	loaderFlagsOffset := int64(0)
	if p.Is64Bit {
		loaderFlagsOffset = optHeaderOffset + 108 // Win64: LoaderFlags (part of OptionalHeader64 specific fields)
	} else {
		loaderFlagsOffset = optHeaderOffset + 92 // Win32: LoaderFlags (part of OptionalHeader32 specific fields)
	}

	if loaderFlagsOffset > 0 && loaderFlagsOffset+4 <= int64(len(p.RawData)) {
		randLoaderFlagsBytes := make([]byte, 4)
		_, err = rand.Read(randLoaderFlagsBytes)
		if err != nil {
			return fmt.Errorf("failed to generate random bytes for LoaderFlags: %w", err)
		}
		copy(p.RawData[loaderFlagsOffset:loaderFlagsOffset+4], randLoaderFlagsBytes)
	} else if loaderFlagsOffset > 0 { // It was calculated but is out of bounds
		return fmt.Errorf("LoaderFlags offset %d out of bounds for file size %d", loaderFlagsOffset, len(p.RawData))
	}
	return nil
}

// ObfuscateSecondaryTimestamps randomizes non-critical timestamps in debug/resource/version sections.
func (p *PEFile) ObfuscateSecondaryTimestamps() error {
	// Cerca stringhe tipo "20xx" o "19xx" in .rsrc/.data/.rdata
	pattern := regexp.MustCompile(`(?m)19\\d{2}|20\\d{2}`)
	for _, section := range p.Sections {
		if section.Name == ".rsrc" || section.Name == ".data" || section.Name == ".rdata" {
			data, err := p.ReadBytes(section.Offset, int(section.Size))
			if err == nil && len(data) >= 4 {
				indices := pattern.FindAllIndex(data, -1)
				for _, idx := range indices {
					// Create a random 4-digit string like "NNNN"
					randDigits := make([]byte, idx[1]-idx[0])
					for k := range randDigits {
						digitRand := make([]byte, 1)
						_, errRead := rand.Read(digitRand)
						if errRead != nil {
							return fmt.Errorf("failed to generate random digit for timestamp in %s: %w", section.Name, errRead)
						}
						randDigits[k] = byte((digitRand[0] % 10) + '0')
					}
					copy(data[idx[0]:idx[1]], randDigits)
				}
				copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
			}
		}
	}
	return nil
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
	if err := p.ObfuscateSectionPadding(); err != nil {
		return fmt.Errorf("error obfuscating section padding: %w", err)
	}
	if err := p.ObfuscateReservedHeaderFields(); err != nil {
		return fmt.Errorf("error obfuscating reserved header fields: %w", err)
	}
	if err := p.ObfuscateSecondaryTimestamps(); err != nil {
		return fmt.Errorf("error obfuscating secondary timestamps: %w", err)
	}
	return nil
}
