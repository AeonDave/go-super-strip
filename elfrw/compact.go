package elfrw

import (
	"gosstrip/common"
	"strings"
)

func (e *ELFFile) Compact(force bool) *common.OperationResult {
	return e.sectionRemoval(force)
}

func (e *ELFFile) identifyCriticalSections() map[int]struct{} {
	critical := make(map[int]struct{})
	for i, sec := range e.Sections {
		name := strings.ToLower(strings.Trim(sec.Name, "\x00"))
		switch name {
		case ".text", ".code",
			".data", ".rodata", ".bss",
			".init", ".fini",
			".plt", ".got", ".got.plt",
			".dynamic", ".dynsym", ".dynstr",
			".hash", ".gnu.hash",
			".interp":
			critical[i] = struct{}{}
		}
		// Go runtime sections that are critical
		if strings.Contains(name, ".go.") ||
			strings.Contains(name, "runtime") ||
			strings.Contains(name, ".eh_frame") ||
			strings.Contains(name, ".ctors") ||
			strings.Contains(name, ".dtors") {
			critical[i] = struct{}{}
		}
	}
	return critical
}

func (e *ELFFile) identifyStripSections(force bool) (removable, keepable []int) {
	rules := GetSectionStripRule()
	critical := e.identifyCriticalSections()

	for i, section := range e.Sections {
		// Never remove critical sections
		if _, ok := critical[i]; ok {
			keepable = append(keepable, i)
			continue
		}

		name := strings.ToLower(strings.Trim(section.Name, "\x00"))
		canStrip := false

		// Check against strip rules
		for _, rule := range rules {
			// Check if this rule applies to our binary type
			isDynamic := e.isDynamic
			if !((isDynamic && rule.StripForSO) || (!isDynamic && rule.StripForEXE)) {
				continue
			}

			// Skip risky operations unless forced
			if rule.IsRisky && !force {
				continue
			}

			// Check exact name matches
			for _, exactName := range rule.ExactNames {
				if name == strings.ToLower(exactName) {
					canStrip = true
					break
				}
			}

			// Check prefix matches
			if !canStrip {
				for _, prefix := range rule.PrefixNames {
					if strings.HasPrefix(name, strings.ToLower(prefix)) {
						canStrip = true
						break
					}
				}
			}

			if canStrip {
				break
			}
		}

		if canStrip {
			removable = append(removable, i)
		} else {
			keepable = append(keepable, i)
		}
	}

	return removable, keepable
}

func (e *ELFFile) sectionRemoval(force bool) *common.OperationResult {
	removable, keepable := e.identifyStripSections(force)

	if len(removable) == 0 {
		return common.NewSkipped("no sections available for removal")
	}

	// Create new section list with only keepable sections
	newSections := make([]Section, 0, len(keepable))
	for _, idx := range keepable {
		newSections = append(newSections, e.Sections[idx])
	}

	// Update section indices
	for i := range newSections {
		newSections[i].Index = i
	}

	removedNames := make([]string, 0, len(removable))
	for _, idx := range removable {
		removedNames = append(removedNames, e.Sections[idx].Name)
	}

	// Update the file structure
	e.Sections = newSections

	message := ""
	if len(removedNames) > 0 {
		message = "removed " + strings.Join(removedNames, ", ")
	}

	return common.NewApplied(message, len(removable))
}

func (e *ELFFile) calculateSizeReduction(removedSections []int) (int64, float64) {
	var removedSize int64
	for _, idx := range removedSections {
		removedSize += e.Sections[idx].Size
	}

	if e.FileSize == 0 {
		return removedSize, 0.0
	}

	percentage := float64(removedSize) / float64(e.FileSize) * 100
	return removedSize, percentage
}
