package pack

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

// PEPolymorphicEngine applica trasformazioni polimorfiche a binari PE
type PEPolymorphicEngine struct {
	*PolymorphicEngine
}

// NewPEPolymorphicEngine crea un engine specifico per PE
func NewPEPolymorphicEngine(config *PackConfig) *PEPolymorphicEngine {
	return &PEPolymorphicEngine{
		PolymorphicEngine: NewPolymorphicEngine(config),
	}
}

// TransformPE applica trasformazioni polimorfiche a un binario PE
func (ppe *PEPolymorphicEngine) TransformPE(peData []byte) ([]byte, []string, error) {
	if !ppe.Config.PolymorphicStub {
		return peData, []string{"none"}, nil
	}

	techniques := []string{}
	result := make([]byte, len(peData))
	copy(result, peData)

	// NON applichiamo più SGN a livello binario perché corrompe il binario compilato
	// Le trasformazioni polimorfiche vengono applicate solo nello stub Go prima della compilazione

	// 1. Modify DOS stub
	result = ppe.randomizeDOSStub(result)
	techniques = append(techniques, "dos_stub_randomization")

	// 2. Modify timestamps
	result = ppe.randomizeTimestamp(result)
	techniques = append(techniques, "timestamp_randomization")

	// 3. Insert random NOPs in code sections
	if ppe.Config.JunkCodeDensity > 0 {
		result = ppe.insertNOPsInCodeSection(result)
		techniques = append(techniques, "nop_insertion")
	}

	// 4. Add fake sections
	result = ppe.addFakeSections(result)
	techniques = append(techniques, "fake_sections")

	// 5. Modify Rich header if present
	result = ppe.randomizeRichHeader(result)
	techniques = append(techniques, "rich_header_randomization")

	// 6. Add overlay data (high entropy)
	result = ppe.addOverlayData(result)
	techniques = append(techniques, "overlay_entropy")

	return result, techniques, nil
}

// randomizeDOSStub modifica il DOS stub (area tra MZ e PE)
func (ppe *PEPolymorphicEngine) randomizeDOSStub(peData []byte) []byte {
	// Verifica che sia un PE valido
	if len(peData) < 128 || !bytes.Equal(peData[0:2], []byte{'M', 'Z'}) {
		return peData
	}

	result := make([]byte, len(peData))
	copy(result, peData)

	// Offset del PE header è a 0x3C (4 bytes)
	peOffset := readUint32LE(result, 0x3C)
	if peOffset < 64 || int(peOffset) > len(result)-4 {
		return result
	}

	// Verifica signature PE
	if !bytes.Equal(result[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
		return result
	}

	// Il DOS stub va da 0x40 fino a peOffset
	// Possiamo modificare questa area (tradizionalmente contiene "This program cannot be run in DOS mode")
	stubStart := 0x40
	stubEnd := int(peOffset)

	if stubStart < stubEnd && stubEnd < len(result) {
		// Mantieni i primi 14 bytes (DOS stub code) ma modifica il messaggio
		messageStart := stubStart + 14
		if messageStart < stubEnd {
			// Genera un messaggio casuale o variazioni
			messages := []string{
				"This program requires Windows.\r\n$",
				"Cannot execute in DOS mode.\r\n$",
				"Windows executable file.\r\n$",
				"Win32 application.\r\n$",
			}
			msg := messages[randomInt(len(messages))]
			msgBytes := []byte(msg)

			// Copia il messaggio casuale
			copyLen := stubEnd - messageStart
			if copyLen > len(msgBytes) {
				copyLen = len(msgBytes)
			}
			copy(result[messageStart:messageStart+copyLen], msgBytes[:copyLen])

			// Riempi il resto con dati casuali o padding
			if messageStart+copyLen < stubEnd {
				rand.Read(result[messageStart+copyLen : stubEnd])
			}
		}
	}

	return result
}

// randomizeTimestamp modifica il timestamp nel PE header
func (ppe *PEPolymorphicEngine) randomizeTimestamp(peData []byte) []byte {
	if len(peData) < 128 {
		return peData
	}

	result := make([]byte, len(peData))
	copy(result, peData)

	// Offset del PE header
	peOffset := readUint32LE(result, 0x3C)
	if peOffset < 64 || int(peOffset)+24 > len(result) {
		return result
	}

	// Il timestamp è a PE_offset + 8 (4 bytes, Unix time)
	timestampOffset := int(peOffset) + 8

	// Genera un timestamp casuale (entro gli ultimi 2 anni)
	randomTimestamp := uint32(1600000000 + randomInt(63072000)) // ~2 anni
	binary.LittleEndian.PutUint32(result[timestampOffset:timestampOffset+4], randomTimestamp)

	return result
}

// insertNOPsInCodeSection inserisce NOPs nella sezione .text
func (ppe *PEPolymorphicEngine) insertNOPsInCodeSection(peData []byte) []byte {
	// Questa funzione richiederebbe parsing completo delle section headers
	// Per ora, cerchiamo zone di padding e inseriamo NOPs casuali

	result := make([]byte, len(peData))
	copy(result, peData)

	// Cerca sequenze di 0x00 lunghe almeno 16 bytes
	paddingStart := -1
	for i := 0; i < len(result)-16; i++ {
		isAllZero := true
		for j := 0; j < 16; j++ {
			if result[i+j] != 0x00 && result[i+j] != 0xCC { // 0xCC = INT3, anche padding
				isAllZero = false
				break
			}
		}

		if isAllZero && paddingStart == -1 {
			paddingStart = i
		} else if !isAllZero && paddingStart != -1 {
			paddingEnd := i
			ppe.fillWithNOPVariants(result[paddingStart:paddingEnd])
			paddingStart = -1
		}
	}

	return result
}

// fillWithNOPVariants riempie con varianti di NOP per x86/x64
func (ppe *PEPolymorphicEngine) fillWithNOPVariants(buffer []byte) {
	nopVariants := [][]byte{
		{0x90},                               // NOP
		{0x66, 0x90},                         // 2-byte NOP
		{0x0F, 0x1F, 0x00},                   // 3-byte NOP
		{0x0F, 0x1F, 0x40, 0x00},             // 4-byte NOP
		{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}, // 6-byte NOP
		{0x8D, 0x80, 0x00, 0x00, 0x00, 0x00}, // LEA EAX, [EAX+0] (6-byte NOP)
	}

	i := 0
	for i < len(buffer) {
		variant := nopVariants[randomInt(len(nopVariants))]
		if i+len(variant) <= len(buffer) {
			copy(buffer[i:], variant)
			i += len(variant)
		} else {
			buffer[i] = 0x90
			i++
		}
	}
}

// addFakeSections aggiunge sezioni dummy al PE
func (ppe *PEPolymorphicEngine) addFakeSections(peData []byte) []byte {
	// Aggiungere sezioni richiede:
	// 1. Parsing del PE header
	// 2. Incremento NumberOfSections
	// 3. Aggiunta di un IMAGE_SECTION_HEADER
	// 4. Append dei dati della sezione

	// Per semplicità, appendiamo solo dati alla fine (overlay)
	fakeDataSize := 64 + randomInt(192) // 64-255 bytes
	fakeData := randomBytes(fakeDataSize)

	result := make([]byte, 0, len(peData)+fakeDataSize)
	result = append(result, peData...)
	result = append(result, fakeData...)

	return result
}

// randomizeRichHeader modifica il Rich header se presente
func (ppe *PEPolymorphicEngine) randomizeRichHeader(peData []byte) []byte {
	// Il Rich header è una struttura non documentata di Microsoft
	// presente tra il DOS stub e il PE header
	// Inizia con "DanS" (in XOR con key) e finisce con "Rich" + key

	result := make([]byte, len(peData))
	copy(result, peData)

	// Cerca il marker "Rich"
	richIdx := bytes.Index(result, []byte("Rich"))
	if richIdx == -1 || richIdx < 128 {
		return result
	}

	// La key è nei 4 bytes dopo "Rich"
	if richIdx+8 > len(result) {
		return result
	}

	// Modifica la key con una casuale
	var newKey uint32
	binary.Read(rand.Reader, binary.LittleEndian, &newKey)
	binary.LittleEndian.PutUint32(result[richIdx+4:richIdx+8], newKey)

	// Trova l'inizio del Rich header (DanS XOR key)
	// e ri-cifra con la nuova key
	// Questo è complesso, per ora modifichiamo solo la key finale

	return result
}

// addOverlayData aggiunge dati ad alta entropia alla fine del PE
func (ppe *PEPolymorphicEngine) addOverlayData(peData []byte) []byte {
	// L'overlay è qualsiasi dato dopo l'ultimo byte del PE
	// Non viene caricato in memoria ma è presente nel file

	overlaySize := 128 + randomInt(384) // 128-511 bytes
	overlayData := randomBytes(overlaySize)

	result := make([]byte, 0, len(peData)+overlaySize)
	result = append(result, peData...)
	result = append(result, overlayData...)

	return result
}

// ModifyImportTable modifica l'import table aggiungendo import dummy
func (ppe *PEPolymorphicEngine) ModifyImportTable(peData []byte) []byte {
	// Questa è una trasformazione avanzata che richiede:
	// 1. Parsing della Import Directory (Data Directory[1])
	// 2. Aggiunta di import fake (DLL che esistono ma funzioni che non usiamo)
	// 3. Aggiustamento dei size fields

	// Per ora, ritorna invariato
	return peData
}

// ReorderSections riordina le sezioni del PE
func (ppe *PEPolymorphicEngine) ReorderSections(peData []byte) []byte {
	// Riordinare le sezioni richiede:
	// 1. Parsing di tutte le section headers
	// 2. Riordino delle sezioni non critiche (.data, .rdata possono muoversi)
	// 3. Aggiornamento dei section headers
	// 4. Aggiornamento dei RVA in import/export tables

	// Implementazione futura
	return peData
}

// AddCertificateTable aggiunge una fake certificate table
func (ppe *PEPolymorphicEngine) AddCertificateTable(peData []byte) []byte {
	// La certificate table (Data Directory[4]) contiene signature digitali
	// Possiamo aggiungerne una fake (invalida) per confondere analisi

	// Implementazione futura: richiede modifica del Data Directory
	return peData
}

// InsertDeadCode inserisce codice morto nelle sezioni eseguibili
func (ppe *PEPolymorphicEngine) InsertDeadCode(peData []byte) []byte {
	// Inserimento di blocchi di codice mai eseguiti:
	// - After RET instructions
	// - In unreachable branches

	// Richiederebbe disassembler
	return peData
}

// EncryptSections cifra sezioni e aggiunge decryptor stub
func (ppe *PEPolymorphicEngine) EncryptSections(peData []byte) []byte {
	// Tecnica avanzata: cifra .text e aggiunge un loader che:
	// 1. Decifra la sezione .text a runtime
	// 2. Salta all'entry point originale

	// Richiede modifica dell'entry point e protezione PAGE_EXECUTE_READWRITE
	return peData
}

// GetMetadata ritorna metadata sulle trasformazioni PE
func (ppe *PEPolymorphicEngine) GetMetadata() *PolymorphicMetadata {
	return &PolymorphicMetadata{
		Techniques:   []string{},
		NOPsInserted: 0,
		EntropyAdded: 0,
	}
}
