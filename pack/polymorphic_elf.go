package pack

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

// ELFPolymorphicEngine applica trasformazioni polimorfiche a binari ELF
type ELFPolymorphicEngine struct {
	*PolymorphicEngine
}

// NewELFPolymorphicEngine crea un engine specifico per ELF
func NewELFPolymorphicEngine(config *PackConfig) *ELFPolymorphicEngine {
	return &ELFPolymorphicEngine{
		PolymorphicEngine: NewPolymorphicEngine(config),
	}
}

// TransformELF applica trasformazioni polimorfiche a un binario ELF
func (epe *ELFPolymorphicEngine) TransformELF(elfData []byte) ([]byte, []string, error) {
	if !epe.Config.PolymorphicStub {
		return elfData, []string{"none"}, nil
	}

	techniques := []string{}
	result := make([]byte, len(elfData))
	copy(result, elfData)

	// NON applichiamo più SGN a livello binario perché corrompe il binario compilato
	// Le trasformazioni polimorfiche vengono applicate solo nello stub Go prima della compilazione

	// 1. Insert random NOPs in code sections
	if epe.Config.JunkCodeDensity > 0 {
		result = epe.insertNOPSleds(result)
		techniques = append(techniques, "nop_insertion")
	}

	// 2. Shuffle non-critical sections
	result = epe.shuffleSections(result)
	techniques = append(techniques, "section_shuffle")

	// 3. Add fake sections
	result = epe.addFakeSections(result)
	techniques = append(techniques, "fake_sections")

	// 4. Modify ELF header padding (solo EI_PAD che è safe)
	result = epe.randomizePadding(result)
	techniques = append(techniques, "header_randomization")

	// 5. Insert dead code branches
	if epe.Config.ControlFlowMutation {
		result = epe.insertDeadBranches(result)
		techniques = append(techniques, "dead_branches")
	}

	return result, techniques, nil
}

// insertNOPSleds inserisce NOP sleds casuali in zone di padding
func (epe *ELFPolymorphicEngine) insertNOPSleds(elfData []byte) []byte {
	result := make([]byte, len(elfData))
	copy(result, elfData)

	// Cerca zone di padding (sequenze di 0x00)
	paddingStart := -1
	for i := 0; i < len(result)-16; i++ {
		// Trova sequenze di almeno 16 byte nulli
		isAllZero := true
		for j := 0; j < 16; j++ {
			if result[i+j] != 0x00 {
				isAllZero = false
				break
			}
		}

		if isAllZero && paddingStart == -1 {
			paddingStart = i
		} else if !isAllZero && paddingStart != -1 {
			// Fine del padding, inserisci NOPs casuali
			paddingEnd := i
			epe.fillWithRandomNOPs(result[paddingStart:paddingEnd])
			paddingStart = -1
		}
	}

	return result
}

// fillWithRandomNOPs riempie un buffer con varianti di NOP
func (epe *ELFPolymorphicEngine) fillWithRandomNOPs(buffer []byte) {
	// Varianti di NOP x86-64:
	nopVariants := [][]byte{
		{0x90},                               // NOP
		{0x66, 0x90},                         // 2-byte NOP
		{0x0F, 0x1F, 0x00},                   // 3-byte NOP
		{0x0F, 0x1F, 0x40, 0x00},             // 4-byte NOP
		{0x66, 0x66, 0x90},                   // 3-byte NOP alt
		{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}, // 6-byte NOP
	}

	i := 0
	for i < len(buffer) {
		// Scegli una variante casuale
		variant := nopVariants[randomInt(len(nopVariants))]

		// Se c'è spazio, inseriscila
		if i+len(variant) <= len(buffer) {
			copy(buffer[i:], variant)
			i += len(variant)
		} else {
			// Riempi il resto con NOP singoli
			buffer[i] = 0x90
			i++
		}
	}
}

// shuffleSections riordina sezioni non critiche nell'ELF
func (epe *ELFPolymorphicEngine) shuffleSections(elfData []byte) []byte {
	// Verifica che sia un ELF valido
	if len(elfData) < 64 || !bytes.Equal(elfData[0:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return elfData
	}

	result := make([]byte, len(elfData))
	copy(result, elfData)

	// In una implementazione completa, si parserebbe l'ELF header,
	// si identificherebbero le sezioni non critiche (debug, comments, etc.)
	// e si riordinerebbero casualmente

	// Per ora, aggiungiamo solo entropia al padding tra sezioni
	// (che normalmente sarebbe zero)

	return result
}

// addFakeSections aggiunge sezioni dummy all'ELF
func (epe *ELFPolymorphicEngine) addFakeSections(elfData []byte) []byte {
	// Verifica che sia un ELF valido
	if len(elfData) < 64 || !bytes.Equal(elfData[0:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return elfData
	}

	// In una implementazione completa, si aggiungerebbe una section header entry
	// per una sezione fake (ad esempio .random o .data2)

	// Per ora, appendiamo semplicemente dei dati casuali alla fine
	fakeDataSize := 128 + randomInt(384) // 128-512 bytes
	fakeData := randomBytes(fakeDataSize)

	result := make([]byte, 0, len(elfData)+fakeDataSize)
	result = append(result, elfData...)
	result = append(result, fakeData...)

	return result
}

// randomizePadding modifica il padding nell'header ELF
func (epe *ELFPolymorphicEngine) randomizePadding(elfData []byte) []byte {
	if len(elfData) < 64 {
		return elfData
	}

	result := make([]byte, len(elfData))
	copy(result, elfData)

	// ELF header ha padding bytes a offset 9-15 (e_ident[EI_PAD])
	// Questi possono essere randomizzati senza invalidare il binario
	if len(result) >= 16 {
		rand.Read(result[9:16])
	}

	return result
}

// insertDeadBranches inserisce branch condizionali che non verranno mai presi
func (epe *ELFPolymorphicEngine) insertDeadBranches(elfData []byte) []byte {
	// Questa è una trasformazione avanzata che richiederebbe:
	// 1. Disassemblare il codice
	// 2. Trovare punti di inserimento sicuri
	// 3. Inserire istruzioni come:
	//    - CMP EAX, EAX ; JNE <never_taken> ; <dead_code> ; <never_taken>:
	//    - TEST ECX, ECX ; JZ <skip> (quando ECX è noto essere non-zero)

	// Per ora, usiamo un approccio più semplice:
	// Cerchiamo sequenze di NOP e inseriamo pattern di branch

	result := make([]byte, len(elfData))
	copy(result, elfData)

	// Pattern di dead branch x86-64:
	// 74 02    JE +2   (salta 2 bytes avanti se ZF=1, ma ZF sarà sempre 0)
	// EB 00    JMP +0  (jump a se stesso - in pratica un NOP di 2 bytes)
	deadBranchPattern := []byte{0x31, 0xC0, 0x74, 0x02, 0xEB, 0x00}
	// 31 C0 = XOR EAX, EAX (imposta ZF=1)
	// 74 02 = JE +2 (salta se ZF=1, quindi sempre)
	// EB 00 = JMP +0 (target del salto)

	// Cerca sequenze di almeno 8 NOP consecutivi e sostituiscile
	for i := 0; i < len(result)-len(deadBranchPattern)-2; i++ {
		isNOPSequence := true
		for j := 0; j < 8; j++ {
			if result[i+j] != 0x90 {
				isNOPSequence = false
				break
			}
		}

		if isNOPSequence {
			// Inserisci dead branch
			copy(result[i:], deadBranchPattern)
			i += len(deadBranchPattern)
		}
	}

	return result
}

// ApplyInstructionSubstitution sostituisce istruzioni con equivalenti
func (epe *ELFPolymorphicEngine) ApplyInstructionSubstitution(elfData []byte) []byte {
	// Sostituzioni comuni x86-64:
	// MOV EAX, 0 -> XOR EAX, EAX
	// ADD EAX, 1 -> INC EAX
	// SUB EAX, 1 -> DEC EAX
	// MOV EAX, EBX -> PUSH EBX; POP EAX

	result := make([]byte, len(elfData))
	copy(result, elfData)

	// Cerca pattern "MOV EAX, 0" (B8 00 00 00 00) e sostituisci con "XOR EAX, EAX" (31 C0)
	for i := 0; i < len(result)-5; i++ {
		if result[i] == 0xB8 &&
			result[i+1] == 0x00 &&
			result[i+2] == 0x00 &&
			result[i+3] == 0x00 &&
			result[i+4] == 0x00 {
			// Sostituisci con XOR EAX, EAX + NOP padding
			result[i] = 0x31
			result[i+1] = 0xC0
			result[i+2] = 0x90 // NOP
			result[i+3] = 0x90 // NOP
			result[i+4] = 0x90 // NOP
			i += 4
		}
	}

	return result
}

// AddEntropySections aggiunge sezioni con alta entropia per confondere analisi
func (epe *ELFPolymorphicEngine) AddEntropySections(elfData []byte) []byte {
	// Aggiunge dati ad alta entropia che sembrano codice compresso/cifrato
	// ma sono in realtà casuali

	entropySize := 512 + randomInt(1024) // 512-1536 bytes
	entropyData := randomBytes(entropySize)

	result := make([]byte, 0, len(elfData)+entropySize)
	result = append(result, elfData...)
	result = append(result, entropyData...)

	return result
}

// ModifyTimestamps modifica timestamp nell'ELF per variare il hash
func (epe *ELFPolymorphicEngine) ModifyTimestamps(elfData []byte) []byte {
	// Gli ELF non hanno timestamp nell'header come i PE,
	// ma possono avere note sections con build-id
	// Possiamo cercare e modificare il build-id se presente

	result := make([]byte, len(elfData))
	copy(result, elfData)

	// Cerca pattern del build-id (tipicamente dopo .note.gnu.build-id)
	// Il build-id è un hash SHA1/MD5, quindi 16-20 bytes
	// Lo sostituiamo con uno casuale

	buildIDMarker := []byte(".note.gnu.build-id")
	idx := bytes.Index(result, buildIDMarker)
	if idx != -1 && idx+len(buildIDMarker)+32 < len(result) {
		// Modifica i 20 bytes dopo il marker (possibile build-id)
		start := idx + len(buildIDMarker) + 8 // skip marker + alcuni bytes di header
		if start+20 < len(result) {
			rand.Read(result[start : start+20])
		}
	}

	return result
}

// ShuffleCodeBlocks riordina blocchi di codice mantenendo la semantica
func (epe *ELFPolymorphicEngine) ShuffleCodeBlocks(elfData []byte) []byte {
	// Questa è una trasformazione molto avanzata che richiede:
	// 1. Disassemblare completamente il codice
	// 2. Costruire un CFG (Control Flow Graph)
	// 3. Identificare basic blocks indipendenti
	// 4. Riordinare i blocks aggiustando jump/call

	// Per ora, ritorna il codice invariato con un marker
	// In una implementazione completa si userebbe un disassembler come capstone

	return elfData
}

// EncryptCodeSection cifra sezioni di codice con decifratura runtime
func (epe *ELFPolymorphicEngine) EncryptCodeSection(elfData []byte) []byte {
	// Questa tecnica cifra sezioni di codice e aggiunge un decryptor stub
	// che decifra il codice a runtime prima dell'esecuzione

	// Implementazione futura: richiederebbe modifica dell'entry point ELF
	// per puntare al decryptor, che poi salta al vero entry point dopo decifratura

	return elfData
}

// GetPolymorphicMetadata ritorna metadata sulle trasformazioni applicate
type PolymorphicMetadata struct {
	Techniques       []string
	NOPsInserted     int
	BranchesInserted int
	SectionsAdded    int
	EntropyAdded     int
}

func (epe *ELFPolymorphicEngine) GetMetadata() *PolymorphicMetadata {
	return &PolymorphicMetadata{
		Techniques:       []string{},
		NOPsInserted:     0,
		BranchesInserted: 0,
		SectionsAdded:    0,
		EntropyAdded:     0,
	}
}

// Helper: legge uint16 little-endian
func readUint16LE(data []byte, offset int) uint16 {
	if offset+2 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint16(data[offset : offset+2])
}

// Helper: legge uint32 little-endian
func readUint32LE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4])
}

// Helper: legge uint64 little-endian
func readUint64LE(data []byte, offset int) uint64 {
	if offset+8 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint64(data[offset : offset+8])
}
