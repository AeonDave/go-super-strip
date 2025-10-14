package pack

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"
	mathrand "math/rand"
	"strings"
)

// SGNPolymorphicEngine implementa tecniche ispirate a Shikata Ga Nai
// per polimorfismo avanzato a livello di bytecode
type SGNPolymorphicEngine struct {
	architecture     int // 32 o 64 bit
	obfuscationLimit int
	seed             byte
}

// NewSGNPolymorphicEngine crea un nuovo engine SGN-style
func NewSGNPolymorphicEngine(arch int) *SGNPolymorphicEngine {
	seedByte := make([]byte, 1)
	rand.Read(seedByte)

	return &SGNPolymorphicEngine{
		architecture:     arch,
		obfuscationLimit: 50,
		seed:             seedByte[0],
	}
}

// CipherSchema definisce operazioni di encoding/decoding
type CipherSchema []struct {
	OP  string
	Key []byte
}

// Operandi logici e aritmetici per encoding
var encodingOperands = []string{"XOR", "SUB", "ADD", "ROL", "ROR", "NOT"}

// CipherADFL (Additive Feedback Loop) - cifratura con XOR additivo in reverse
// Tecnica principale di Shikata Ga Nai
func CipherADFL(data []byte, seed byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)

	// Processo in ordine INVERSO (caratteristica di SGN)
	for i := 1; i < len(result)+1; i++ {
		current := result[len(result)-i]
		result[len(result)-i] ^= seed
		seed = byte((int(current) + int(seed)) % 256)
	}

	return result
}

// SchemaCipher applica uno schema di cifratura multi-operando
func (sgn *SGNPolymorphicEngine) SchemaCipher(data []byte, startIndex int, schema CipherSchema) []byte {
	result := make([]byte, len(data))
	copy(result, data)

	index := startIndex
	for _, cursor := range schema {
		if index+4 > len(result) {
			break
		}

		switch cursor.OP {
		case "XOR":
			value := binary.LittleEndian.Uint32(result[index : index+4])
			key := binary.BigEndian.Uint32(cursor.Key)
			binary.LittleEndian.PutUint32(result[index:index+4], value^key)

		case "ADD":
			value := binary.LittleEndian.Uint32(result[index : index+4])
			key := binary.BigEndian.Uint32(cursor.Key)
			binary.LittleEndian.PutUint32(result[index:index+4], (value-key)%0xFFFFFFFF)

		case "SUB":
			value := binary.LittleEndian.Uint32(result[index : index+4])
			key := binary.BigEndian.Uint32(cursor.Key)
			binary.LittleEndian.PutUint32(result[index:index+4], (value+key)%0xFFFFFFFF)

		case "ROL":
			value := binary.LittleEndian.Uint32(result[index : index+4])
			rotate := -int(binary.BigEndian.Uint32(cursor.Key))
			binary.LittleEndian.PutUint32(result[index:index+4], bits.RotateLeft32(value, rotate))

		case "ROR":
			value := binary.LittleEndian.Uint32(result[index : index+4])
			rotate := int(binary.BigEndian.Uint32(cursor.Key))
			binary.LittleEndian.PutUint32(result[index:index+4], bits.RotateLeft32(value, rotate))

		case "NOT":
			value := binary.BigEndian.Uint32(result[index : index+4])
			binary.BigEndian.PutUint32(result[index:index+4], ^value)
		}

		index += 4
	}

	return result
}

// NewCipherSchema genera uno schema casuale di operazioni di cifratura
func (sgn *SGNPolymorphicEngine) NewCipherSchema(size int) CipherSchema {
	schema := make(CipherSchema, size)

	for i := range schema {
		op := encodingOperands[mathrand.Intn(len(encodingOperands))]
		schema[i].OP = op

		if op == "NOT" {
			schema[i].Key = nil
		} else if op == "ROL" || op == "ROR" {
			// Per rotazioni, usa solo il byte meno significativo
			schema[i].Key = []byte{0, 0, 0, getRandomByte()}
		} else {
			// 4 byte per altre operazioni
			schema[i].Key = getRandomBytes(4)
		}
	}

	return schema
}

// GenerateGarbageAssembly genera istruzioni assembly casuali "safe"
func (sgn *SGNPolymorphicEngine) GenerateGarbageAssembly() string {
	// Istruzioni "safe" che non modificano lo stato critico
	safeInstructions := []string{
		"NOP;",
		"PUSH {R}; POP {R};",
		"MOV {R}, {R};",
		"LEA {R}, [{R}+0];",
		"TEST {R}, {R};",
		"CMP {R}, 0x{K};",
		"ADD {R}, 0x{K}; SUB {R}, 0x{K};",
		"XOR {R}, 0x{K}; XOR {R}, 0x{K};",
		"SHL {R}, 0; SHR {R}, 0;",
	}

	if !coinFlip() {
		return ";"
	}

	instruction := safeInstructions[mathrand.Intn(len(safeInstructions))]
	register := sgn.getRandomRegister()
	randomByte := getRandomByte()

	instruction = strings.ReplaceAll(instruction, "{R}", register)
	instruction = strings.ReplaceAll(instruction, "{K}", fmt.Sprintf("%02x", randomByte))

	return instruction
}

// GenerateConditionalJump genera salti condizionali con garbage code
func (sgn *SGNPolymorphicEngine) GenerateConditionalJump() string {
	// Jump mnemonics condizionali
	conditionalJumps := []string{
		"JE", "JNE", "JZ", "JNZ", "JG", "JGE", "JL", "JLE",
		"JA", "JAE", "JB", "JBE", "JS", "JNS", "JO", "JNO",
	}

	label := randomLabel()
	jmp := conditionalJumps[mathrand.Intn(len(conditionalJumps))]

	// Genera pattern: TEST reg, reg; JMP label; garbage; label:
	register := sgn.getRandomRegister()
	garbage := sgn.GenerateGarbageAssembly()

	return fmt.Sprintf("TEST %s, %s; %s %s; %s %s:;", register, register, jmp, label, garbage, label)
}

// GenerateFunctionFrame genera un frame di funzione con garbage
func (sgn *SGNPolymorphicEngine) GenerateFunctionFrame() string {
	var bp, sp string

	if sgn.architecture == 64 {
		bp = "RBP"
		sp = "RSP"
	} else {
		bp = "EBP"
		sp = "ESP"
	}

	prologue := fmt.Sprintf("PUSH %s; MOV %s, %s; SUB %s, 0x%x;",
		bp, bp, sp, sp, getRandomByte())

	body := sgn.GenerateGarbageAssembly()

	epilogue := fmt.Sprintf("MOV %s, %s; POP %s;", sp, bp, bp)

	return prologue + body + epilogue
}

// GenerateJumpOver genera un JMP che salta sopra bytes casuali
func (sgn *SGNPolymorphicEngine) GenerateJumpOver(garbageSize int) []byte {
	// JMP istruzione: EB <offset> (2 bytes per short jump)
	// offset = numero di bytes da saltare

	if garbageSize > 127 {
		garbageSize = 127 // short jump limit
	}

	garbage := getRandomBytes(garbageSize)

	// EB = short JMP, offset relativo
	jmpInstruction := []byte{0xEB, byte(garbageSize)}

	result := append(jmpInstruction, garbage...)
	return result
}

// ApplyPolymorphicTransform applica trasformazioni SGN-style a bytecode
func (sgn *SGNPolymorphicEngine) ApplyPolymorphicTransform(code []byte) ([]byte, error) {
	// 1. Cifra il payload con ADFL
	ciphered := CipherADFL(code, sgn.seed)

	// 2. Genera schema casuale per ulteriore obfuscation
	schemaSize := (len(ciphered) / 4) + 1
	schema := sgn.NewCipherSchema(schemaSize)

	// 3. Applica schema cipher
	obfuscated := sgn.SchemaCipher(ciphered, 0, schema)

	// 4. Inserisci garbage instructions casuali
	garbage, _ := sgn.GenerateGarbageInstructions()
	result := append(garbage, obfuscated...)

	return result, nil
}

// GenerateGarbageInstructions genera istruzioni garbage come bytes
func (sgn *SGNPolymorphicEngine) GenerateGarbageInstructions() ([]byte, error) {
	// Genera alcune istruzioni NOP variants
	nopVariants := [][]byte{
		{0x90},                   // NOP
		{0x66, 0x90},             // 2-byte NOP
		{0x0F, 0x1F, 0x00},       // 3-byte NOP
		{0x0F, 0x1F, 0x40, 0x00}, // 4-byte NOP
	}

	count := mathrand.Intn(5) + 1 // 1-5 NOPs
	result := []byte{}

	for i := 0; i < count; i++ {
		variant := nopVariants[mathrand.Intn(len(nopVariants))]
		result = append(result, variant...)
	}

	// Aggiungi un jump over random bytes
	if coinFlip() && len(result) < sgn.obfuscationLimit {
		jumpSize := mathrand.Intn(sgn.obfuscationLimit / 10)
		jumpOver := sgn.GenerateJumpOver(jumpSize)
		result = append(result, jumpOver...)
	}

	return result, nil
}

// getRandomRegister ritorna un registro casuale per l'architettura
func (sgn *SGNPolymorphicEngine) getRandomRegister() string {
	if sgn.architecture == 64 {
		regs := []string{"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11"}
		return regs[mathrand.Intn(len(regs))]
	}
	regs := []string{"EAX", "EBX", "ECX", "EDX", "ESI", "EDI"}
	return regs[mathrand.Intn(len(regs))]
}

// Helper functions
func getRandomByte() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]
}

func getRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func coinFlip() bool {
	return mathrand.Intn(2) == 0
}

func randomLabel() string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 5)
	for i := range b {
		b[i] = letters[mathrand.Intn(len(letters))]
	}
	return string(b)
}

// GetSchemaDescription ritorna una descrizione dello schema di cifratura
func GetSchemaDescription(schema CipherSchema) string {
	var sb strings.Builder
	sb.WriteString("Cipher Schema:\n")
	for i, s := range schema {
		if s.Key == nil {
			sb.WriteString(fmt.Sprintf("  [%d] %s: 0x00000000\n", i, s.OP))
		} else {
			sb.WriteString(fmt.Sprintf("  [%d] %s: 0x%x\n", i, s.OP, s.Key))
		}
	}
	return sb.String()
}

// ApplySGNToELF applica trasformazioni SGN a un binario ELF
func ApplySGNToELF(elfData []byte, config *PackConfig) ([]byte, []string, error) {
	sgn := NewSGNPolymorphicEngine(64)

	techniques := []string{}
	result := make([]byte, len(elfData))
	copy(result, elfData)

	// 1. Trova zone di padding e applica ADFL cipher
	paddingZones := findPaddingZones(result, 64)
	for _, zone := range paddingZones {
		// Skip l'header ELF (primi 64 bytes sono critici)
		if zone.start < 64 {
			continue
		}
		if zone.end-zone.start >= 64 {
			// Cifra la zona di padding
			paddingData := result[zone.start:zone.end]
			ciphered := CipherADFL(paddingData, sgn.seed)
			copy(result[zone.start:zone.end], ciphered)
			techniques = append(techniques, "adfl_cipher")
		}
	}

	// 2. Inserisci garbage instructions e jump-over patterns
	for _, zone := range paddingZones {
		// Skip header
		if zone.start < 64 {
			continue
		}
		if zone.end-zone.start >= 16 {
			// Inserisci jump-over pattern
			jumpOver := sgn.GenerateJumpOver(8)
			if zone.start+len(jumpOver) < zone.end {
				copy(result[zone.start:zone.start+len(jumpOver)], jumpOver)
				techniques = append(techniques, "jump_over")
			}
		}
	}

	// 3. NON modificare l'header critico (primi 64 bytes)
	// Ma possiamo modificare il padding dentro l'header (bytes 9-15 in e_ident)
	if len(result) >= 16 {
		// EI_PAD bytes (9-15) possono essere modificati senza problemi
		rand.Read(result[9:16])
		techniques = append(techniques, "header_pad_randomization")
	}

	if config.Verbose {
		fmt.Printf("   SGN techniques applied: %v\n", techniques)
		fmt.Printf("   ADFL seed: 0x%02x\n", sgn.seed)
	}

	return result, techniques, nil
}

// ApplySGNToPE applica trasformazioni SGN a un binario PE
func ApplySGNToPE(peData []byte, config *PackConfig) ([]byte, []string, error) {
	sgn := NewSGNPolymorphicEngine(64)

	techniques := []string{}
	result := make([]byte, len(peData))
	copy(result, peData)

	// Trova zone di padding nel PE
	paddingZones := findPaddingZones(result, 64)

	// Applica ADFL cipher alle zone di padding
	for _, zone := range paddingZones {
		if zone.end-zone.start >= 64 {
			paddingData := result[zone.start:zone.end]
			ciphered := CipherADFL(paddingData, sgn.seed)
			copy(result[zone.start:zone.end], ciphered)
			techniques = append(techniques, "adfl_cipher")
		}
	}

	// Inserisci jump-over patterns
	for _, zone := range paddingZones {
		if zone.end-zone.start >= 16 {
			jumpOver := sgn.GenerateJumpOver(8)
			if zone.start+len(jumpOver) < zone.end {
				copy(result[zone.start:zone.start+len(jumpOver)], jumpOver)
				techniques = append(techniques, "jump_over")
			}
		}
	}

	if config.Verbose {
		fmt.Printf("   SGN techniques applied: %v\n", techniques)
	}

	return result, techniques, nil
}

// paddingZone rappresenta una zona di padding nel binario
type paddingZone struct {
	start int
	end   int
}

// findPaddingZones trova zone di padding (sequenze di 0x00 o 0xCC)
func findPaddingZones(data []byte, minSize int) []paddingZone {
	zones := []paddingZone{}
	inPadding := false
	currentStart := 0

	for i := 0; i < len(data); i++ {
		if data[i] == 0x00 || data[i] == 0xCC {
			if !inPadding {
				currentStart = i
				inPadding = true
			}
		} else {
			if inPadding {
				if i-currentStart >= minSize {
					zones = append(zones, paddingZone{start: currentStart, end: i})
				}
				inPadding = false
			}
		}
	}

	// Chiudi l'ultima zona se ancora in padding
	if inPadding && len(data)-currentStart >= minSize {
		zones = append(zones, paddingZone{start: currentStart, end: len(data)})
	}

	return zones
}
