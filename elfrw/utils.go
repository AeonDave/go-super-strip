package elfrw

// Utility functions for accessing ELF file properties

func (e *ELFFile) GetFileType() uint16 {
	return uint16(e.ELF.GetFileType())
}

func (e *ELFFile) GetSegmentCount() uint16 {
	return e.ELF.GetSegmentCount()
}

func (e *ELFFile) GetSectionCount() uint16 {
	return e.ELF.GetSectionCount()
}

func (e *ELFFile) GetProgramHeader(index uint16) (interface{}, error) {
	return e.ELF.GetProgramHeader(index)
}

func (e *ELFFile) GetSectionHeader(index uint16) (interface{}, error) {
	return e.ELF.GetSectionHeader(index)
}

func (e *ELFFile) GetSectionName(index uint16) (string, error) {
	return e.ELF.GetSectionName(index)
}

func (e *ELFFile) GetSectionContent(index uint16) ([]byte, error) {
	return e.ELF.GetSectionContent(index)
}

func (e *ELFFile) GetSegmentContent(index uint16) ([]byte, error) {
	return e.ELF.GetSegmentContent(index)
}

func (e *ELFFile) IsStringTable(index uint16) bool {
	return e.ELF.IsStringTable(index)
}

func (e *ELFFile) IsSymbolTable(index uint16) bool {
	return e.ELF.IsSymbolTable(index)
}

func (e *ELFFile) IsRelocationTable(index uint16) bool {
	return e.ELF.IsRelocationTable(index)
}

func (e *ELFFile) IsDynamicSection(index uint16) bool {
	return e.ELF.IsDynamicSection(index)
}
