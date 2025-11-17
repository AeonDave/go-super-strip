package perw

import "gosstrip/common"

// sectionMatchesRule determines whether a section matches the provided rule,
// respecting risky flags and EXE/DLL specific guards.
func (p *PEFile) sectionMatchesRule(sectionType SectionType, section *Section, rule SectionStripRule, force bool) bool {
	if section == nil {
		return false
	}
	if rule.IsRisky && !force {
		return false
	}
	if !p.shouldStripForFileType(sectionType) {
		return false
	}
	return common.MatchesPattern(section.Name, rule.ExactNames, rule.PrefixNames)
}

// wipeSectionData overwrites the section payload according to the specified fill strategy.
func (p *PEFile) wipeSectionData(section *Section, fillMode FillMode) error {
	if section == nil {
		return nil
	}
	if section.Offset <= 0 || section.Size <= 0 {
		return nil
	}
	return p.fillRegion(section.Offset, int(section.Size), fillMode)
}
