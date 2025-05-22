package elfrw

// Funzioni di utilità per accedere alle proprietà del file ELF

// GetFileType restituisce il tipo di file ELF
func (e *ELFFile) GetFileType() uint16 {
	return uint16(e.ELF.GetFileType())
}

// GetSegmentCount restituisce il numero di intestazioni di programma
func (e *ELFFile) GetSegmentCount() uint16 {
	return e.ELF.GetSegmentCount()
}

// GetSectionCount restituisce il numero di intestazioni di sezione
func (e *ELFFile) GetSectionCount() uint16 {
	return e.ELF.GetSectionCount()
}

// GetProgramHeader restituisce l'intestazione di programma all'indice specificato
func (e *ELFFile) GetProgramHeader(index uint16) (interface{}, error) {
	return e.ELF.GetProgramHeader(index)
}

// GetSectionHeader restituisce l'intestazione di sezione all'indice specificato
func (e *ELFFile) GetSectionHeader(index uint16) (interface{}, error) {
	return e.ELF.GetSectionHeader(index)
}

// GetSectionName restituisce il nome della sezione all'indice specificato
func (e *ELFFile) GetSectionName(index uint16) (string, error) {
	return e.ELF.GetSectionName(index)
}

// GetSectionContent restituisce il contenuto della sezione all'indice specificato
func (e *ELFFile) GetSectionContent(index uint16) ([]byte, error) {
	return e.ELF.GetSectionContent(index)
}

// GetSegmentContent restituisce il contenuto del segmento all'indice specificato
func (e *ELFFile) GetSegmentContent(index uint16) ([]byte, error) {
	return e.ELF.GetSegmentContent(index)
}

// IsStringTable verifica se la sezione all'indice specificato è una tabella di stringhe
func (e *ELFFile) IsStringTable(index uint16) bool {
	return e.ELF.IsStringTable(index)
}

// IsSymbolTable verifica se la sezione all'indice specificato è una tabella di simboli
func (e *ELFFile) IsSymbolTable(index uint16) bool {
	return e.ELF.IsSymbolTable(index)
}

// IsRelocationTable verifica se la sezione all'indice specificato è una tabella di rilocazioni
func (e *ELFFile) IsRelocationTable(index uint16) bool {
	return e.ELF.IsRelocationTable(index)
}

// IsDynamicSection verifica se la sezione all'indice specificato è una sezione dinamica
func (e *ELFFile) IsDynamicSection(index uint16) bool {
	return e.ELF.IsDynamicSection(index)
}
