package perw

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
)

var (
	DebugSectionsExact = []string{
		".debug", ".pdata", ".xdata", ".debug$S", ".debug$T", ".debug$P", ".debug$F",
	}
	SymbolSectionsExact = []string{
		".symtab", ".strtab",
	}
	RelocSectionsExact = []string{
		".reloc",
	}
	NonEssentialSectionsExact = []string{
		".comment", ".note", ".drectve", ".rsrc",
	}
	ExceptionSectionsExact = []string{
		".pdata", ".xdata",
	}
	BuildInfoSectionsExact = []string{
		".buildid", ".gfids", ".giats", ".gljmp",
	}
)

// ZeroFill fills a memory region with zeros.
func (p *PEFile) ZeroFill(offset int64, size int) error {
	if offset+int64(size) > int64(len(p.RawData)) {
		return fmt.Errorf("write beyond file limits: offset %d, size %d", offset, size)
	}
	for i := int64(0); i < int64(size); i++ {
		p.RawData[offset+i] = 0
	}
	return nil
}

// ReadBytes reads a specified number of bytes from an offset.
func (p *PEFile) ReadBytes(offset int64, size int) ([]byte, error) {
	if offset+int64(size) > int64(len(p.RawData)) {
		return nil, fmt.Errorf("read beyond file limits: offset %d, size %d", offset, size)
	}
	return p.RawData[offset : offset+int64(size)], nil
}

// StripSectionsByNames removes sections by their names.
func (p *PEFile) StripSectionsByNames(names []string, prefix bool) error {
	for i, section := range p.Sections {
		for _, name := range names {
			if (prefix && strings.HasPrefix(section.Name, name)) || (!prefix && section.Name == name) {
				if section.Offset > 0 && section.Size > 0 {
					if err := p.ZeroFill(section.Offset, int(section.Size)); err != nil {
						return err
					}
				}
				p.Sections[i].Offset, p.Sections[i].Size = 0, 0
			}
		}
	}
	return p.UpdateSectionHeaders()
}

// StripDebugInfo removes debug sections.
func (p *PEFile) StripDebugInfo() error {
	return p.StripSectionsByNames(DebugSectionsExact, false)
}

// StripSymbols removes symbol tables.
func (p *PEFile) StripSymbols() error {
	return p.StripSectionsByNames(SymbolSectionsExact, false)
}

// StripRelocationInfo removes relocation information.
func (p *PEFile) StripRelocationInfo() error {
	return p.StripSectionsByNames(RelocSectionsExact, false)
}

// StripNonEssentialData removes non-essential data.
func (p *PEFile) StripNonEssentialData() error {
	return p.StripSectionsByNames(NonEssentialSectionsExact, false)
}

// StripExceptionHandling removes exception handling information.
func (p *PEFile) StripExceptionHandling() error {
	return p.StripSectionsByNames(ExceptionSectionsExact, false)
}

// StripBuildInfo removes build information.
func (p *PEFile) StripBuildInfo() error {
	return p.StripSectionsByNames(BuildInfoSectionsExact, false)
}

// StripAllMetadata removes all non-essential metadata.
func (p *PEFile) StripAllMetadata() error {
	if err := p.StripDebugInfo(); err != nil {
		return err
	}
	if err := p.StripSymbols(); err != nil {
		return err
	}
	if !p.IsDLL() {
		if err := p.StripRelocationInfo(); err != nil {
			return err
		}
	}
	if err := p.StripNonEssentialData(); err != nil {
		return err
	}
	if err := p.StripExceptionHandling(); err != nil {
		return err
	}
	if err := p.StripBuildInfo(); err != nil {
		return err
	}
	return p.RandomizeSectionNames()
}

// ModifyPEHeader modifies non-essential PE header fields.
func (p *PEFile) ModifyPEHeader() error {
	if len(p.RawData) < 0x40 {
		return fmt.Errorf("file too small for DOS header")
	}
	e_lfanew := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	tsOffset := e_lfanew + 8
	return WriteAtOffset(p.RawData, tsOffset, uint32(rand.Intn(0x7FFFFFFF)))
}

// RandomizeSectionNames renames sections with random names.
func (p *PEFile) RandomizeSectionNames() error {
	if len(p.RawData) < 0x40 {
		return fmt.Errorf("file too small for DOS header")
	}
	e_lfanew := int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40]))
	sizeOfOptionalHeader := int64(binary.LittleEndian.Uint16(p.RawData[e_lfanew+20 : e_lfanew+22]))
	sectionTableOffset := e_lfanew + 24 + sizeOfOptionalHeader

	for i := range p.Sections {
		randomName := fmt.Sprintf(".s%04x", rand.Intn(0xFFFF))[:8]
		copy(p.RawData[sectionTableOffset+int64(i*40):], []byte(randomName))
		p.Sections[i].Name = randomName
	}
	return nil
}

// StripByteRegex overwrites byte patterns matching a regex with null bytes in all sections.
func (p *PEFile) StripByteRegex(pattern *regexp.Regexp) int {
	matchesTotal := 0
	for _, section := range p.Sections {
		if section.Offset <= 0 || section.Size <= 0 {
			continue
		}
		data, err := p.ReadBytes(section.Offset, int(section.Size))
		if err != nil {
			continue
		}
		indices := pattern.FindAllIndex(data, -1)
		if len(indices) == 0 {
			continue
		}
		for _, idx := range indices {
			for i := idx[0]; i < idx[1]; i++ {
				data[i] = 0
			}
			matchesTotal++
		}
		copy(p.RawData[section.Offset:section.Offset+int64(section.Size)], data)
	}
	return matchesTotal
}
