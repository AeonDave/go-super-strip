package pack

import (
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"strings"
	"time"
)

// StubVariant definisce una variante dello stub decoder
type StubVariant struct {
	Name              string   // Nome identificativo
	SourceCode        string   // Codice Go della variante
	DecryptionPattern string   // Pattern di decryption usato
	UniqueFeatures    []string // Caratteristiche uniche
}

// StubTemplateGenerator genera varianti polimorfiche dello stub
type StubTemplateGenerator struct {
	seed              int64
	rng               *mathrand.Rand
	instructionEngine *InstructionSubstitutionEngine
}

// NewStubTemplateGenerator crea un nuovo generator
func NewStubTemplateGenerator() *StubTemplateGenerator {
	seedBytes := make([]byte, 8)
	_, _ = rand.Read(seedBytes)
	seed := time.Now().UnixNano()

	return &StubTemplateGenerator{
		seed:              seed,
		rng:               mathrand.New(mathrand.NewSource(seed)),
		instructionEngine: NewInstructionSubstitutionEngine(seed),
	}
}

// GenerateVariant genera una variante casuale dello stub
func (stg *StubTemplateGenerator) GenerateVariant(variantID int) *StubVariant {
	// Seleziona pattern casuale
	patterns := []string{
		"forward_xor",
		"reverse_xor",
		"additive_feedback",
		"xor_rotate",
		"multi_pass",
		"block_cipher_random", // NEW
		"control_flow_obf",    // NEW
	}

	pattern := patterns[stg.rng.Intn(len(patterns))]

	// Genera nomi variabili casuali
	varNames := stg.generateVariableNames()

	// Genera codice basato sul pattern
	var sourceCode string
	var features []string

	switch pattern {
	case "forward_xor":
		sourceCode = stg.generateForwardXOR(varNames)
		features = []string{"forward_iteration", "simple_xor", "instruction_subst"}

	case "reverse_xor":
		sourceCode = stg.generateReverseXOR(varNames)
		features = []string{"reverse_iteration", "simple_xor", "instruction_subst"}

	case "additive_feedback":
		sourceCode = stg.generateAdditiveFeedback(varNames)
		features = []string{"forward_iteration", "feedback_loop", "additive_cipher"}

	case "xor_rotate":
		sourceCode = stg.generateXORRotate(varNames)
		features = []string{"forward_iteration", "bit_rotation", "xor"}

	case "multi_pass":
		sourceCode = stg.generateMultiPass(varNames)
		features = []string{"multi_pass_decrypt", "xor", "additive"}

	case "block_cipher_random":
		sourceCode = stg.generateBlockCipherRandom(varNames)
		features = []string{"block_cipher", "random_ops", "multi_operation"}

	case "control_flow_obf":
		sourceCode = stg.generateControlFlowObfuscated(varNames)
		features = []string{"control_flow_obf", "switch_based", "complex_flow"}
	}

	return &StubVariant{
		Name:              fmt.Sprintf("variant_%d_%s", variantID, pattern),
		SourceCode:        sourceCode,
		DecryptionPattern: pattern,
		UniqueFeatures:    features,
	}
}

// generateVariableNames genera nomi di variabili casuali
func (stg *StubTemplateGenerator) generateVariableNames() map[string]string {
	// Pool di nomi possibili
	prefixes := []string{"d", "x", "p", "buf", "tmp", "val", "k", "r", "s"}
	suffixes := []string{"ata", "tr", "ff", "ey", "eg", "em", "nt", ""}

	getName := func() string {
		prefix := prefixes[stg.rng.Intn(len(prefixes))]
		suffix := suffixes[stg.rng.Intn(len(suffixes))]
		return prefix + suffix
	}

	return map[string]string{
		"data":   getName(),
		"key":    getName(),
		"i":      getName(),
		"temp":   getName(),
		"offset": getName(),
		"size":   getName(),
	}
}

// generateForwardXOR genera decoder con XOR forward
func (stg *StubTemplateGenerator) generateForwardXOR(vars map[string]string) string {
	// Genera garbage code casuale
	garbage := stg.generateGarbageCode()

	template := `
// Variant: Forward XOR Decryption
func decryptPayload_%[1]s({{DATA}} []byte, {{KEY}} byte) {
	%[2]s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		{{DATA}}[{{I}}] ^= {{KEY}}
		%[3]s
	}
}
`

	code := fmt.Sprintf(template,
		stg.generateRandomString(8),
		garbage[0],
		garbage[1])

	// Sostituisci placeholders con nomi variabili
	for placeholder, varName := range vars {
		code = strings.ReplaceAll(code, "{{"+strings.ToUpper(placeholder)+"}}", varName)
	}

	return code
}

// generateReverseXOR genera decoder con XOR reverse
func (stg *StubTemplateGenerator) generateReverseXOR(vars map[string]string) string {
	garbage := stg.generateGarbageCode()

	template := `
// Variant: Reverse XOR Decryption
func decryptPayload_%[1]s({{DATA}} []byte, {{KEY}} byte) {
	%[2]s
	for {{I}} := len({{DATA}}) - 1; {{I}} >= 0; {{I}}-- {
		%[3]s
		{{DATA}}[{{I}}] ^= {{KEY}}
	}
}
`

	code := fmt.Sprintf(template,
		stg.generateRandomString(8),
		garbage[0],
		garbage[1])

	for placeholder, varName := range vars {
		code = strings.ReplaceAll(code, "{{"+strings.ToUpper(placeholder)+"}}", varName)
	}

	return code
}

// generateAdditiveFeedback genera decoder con ADFL (come Shikata Ga Nai)
func (stg *StubTemplateGenerator) generateAdditiveFeedback(vars map[string]string) string {
	garbage := stg.generateGarbageCode()

	template := `
// Variant: Additive Feedback Loop (ADFL)
func decryptPayload_%[1]s({{DATA}} []byte, {{KEY}} byte) {
	%[2]s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		{{TEMP}} := {{DATA}}[{{I}}]
		{{DATA}}[{{I}}] ^= {{KEY}}
		{{KEY}} = byte((int({{TEMP}}) + int({{KEY}})) %% 256)
		%[3]s
	}
}
`

	code := fmt.Sprintf(template,
		stg.generateRandomString(8),
		garbage[0],
		garbage[1])

	for placeholder, varName := range vars {
		code = strings.ReplaceAll(code, "{{"+strings.ToUpper(placeholder)+"}}", varName)
	}

	return code
}

// generateXORRotate genera decoder con XOR + bit rotation
func (stg *StubTemplateGenerator) generateXORRotate(vars map[string]string) string {
	garbage := stg.generateGarbageCode()
	rotateAmount := stg.rng.Intn(7) + 1 // 1-7 bits

	template := `
// Variant: XOR with Key Rotation
func decryptPayload_%[1]s({{DATA}} []byte, {{KEY}} byte) {
	%[2]s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		{{DATA}}[{{I}}] ^= {{KEY}}
		%[3]s
		// Rotate key
		{{KEY}} = ({{KEY}} << %[4]d) | ({{KEY}} >> (8 - %[4]d))
	}
}
`

	code := fmt.Sprintf(template,
		stg.generateRandomString(8),
		garbage[0],
		garbage[1],
		rotateAmount)

	for placeholder, varName := range vars {
		code = strings.ReplaceAll(code, "{{"+strings.ToUpper(placeholder)+"}}", varName)
	}

	return code
}

// generateMultiPass genera decoder multi-pass
func (stg *StubTemplateGenerator) generateMultiPass(vars map[string]string) string {
	garbage := stg.generateGarbageCode()

	template := `
	// Variant: Multi-Pass Decryption
	func decryptPayload_%[1]s({{DATA}} []byte, {{KEY}} byte) {
		%[2]s
		// First pass: XOR
		for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
			{{DATA}}[{{I}}] ^= {{KEY}}
		}
		%[3]s
		// Second pass: ADD
		{{OFFSET}} := byte({{KEY}} * 3)
		for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
			{{DATA}}[{{I}}] = byte((int({{DATA}}[{{I}}]) - int({{OFFSET}})) %% 256)
		}
	}
	`

	code := fmt.Sprintf(template,
		stg.generateRandomString(8),
		garbage[0],
		garbage[1])

	for placeholder, varName := range vars {
		code = strings.ReplaceAll(code, "{{"+strings.ToUpper(placeholder)+"}}", varName)
	}

	return code
}

// generateGarbageCode genera linee di codice "garbage" innocuo
func (stg *StubTemplateGenerator) generateGarbageCode() []string {
	garbagePatterns := [][]string{
		{
			"// Initialization",
			"// Processing",
		},
		{
			"_ = len({{DATA}}) // size check",
			"// Continue decryption",
		},
		{
			"if len({{DATA}}) == 0 { return }",
			"// Decrypt byte",
		},
		{
			"var _ = {{KEY}} // key validation",
			"// Apply transform",
		},
		{
			"// Anti-debug check placeholder",
			"// Transformation step",
		},
	}

	return garbagePatterns[stg.rng.Intn(len(garbagePatterns))]
}

// generateRandomString genera una stringa casuale
func (stg *StubTemplateGenerator) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[stg.rng.Intn(len(charset))]
	}
	return string(result)
}

// generateBlockCipherRandom genera decoder con operazioni cipher casuali
func (stg *StubTemplateGenerator) generateBlockCipherRandom(vars map[string]string) string {
	garbage := stg.generateGarbageCode()

	// Genera operazione cipher casuale
	cipherOp := stg.instructionEngine.GenerateBlockCipherOps("{{DATA}}[{{I}}]", "{{KEY}}")

	template := `
// Variant: Block Cipher Random Operations
func decryptPayload_%[1]s({{DATA}} []byte, {{KEY}} byte) {
	%[2]s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		%[3]s
		%[4]s
	}
}
`

	code := fmt.Sprintf(template,
		stg.generateRandomString(8),
		garbage[0],
		cipherOp,
		garbage[1])

	for placeholder, varName := range vars {
		code = strings.ReplaceAll(code, "{{"+strings.ToUpper(placeholder)+"}}", varName)
	}

	return code
}

// generateControlFlowObfuscated genera decoder con control flow obfuscato
func (stg *StubTemplateGenerator) generateControlFlowObfuscated(vars map[string]string) string {
	garbage := stg.generateGarbageCode()

	// Genera storage variant casuale
	storageVariant := stg.rng.Intn(3)
	var storageDecl, dataAccess, keyAccess string

	switch storageVariant {
	case 0: // Array
		storageDecl = "var {{TEMP}}Storage [2]byte"
		dataAccess = "{{TEMP}}Storage[0]"
		keyAccess = "{{TEMP}}Storage[1]"
	case 1: // Slice
		storageDecl = "{{TEMP}}Storage := make([]byte, 2)"
		dataAccess = "{{TEMP}}Storage[0]"
		keyAccess = "{{TEMP}}Storage[1]"
	case 2: // Direct
		storageDecl = "var {{TEMP}}Data, {{TEMP}}Key byte"
		dataAccess = "{{TEMP}}Data"
		keyAccess = "{{TEMP}}Key"
	}

	// Usa switch invece di if per control flow
	template := `
// Variant: Control Flow Obfuscated with Switch
func decryptPayload_%[1]s({{DATA}} []byte, {{KEY}} byte) {
	%[2]s
	%[5]s
	{{I}} := 0
	for {
		switch {
		case {{I}} >= len({{DATA}}):
			return
		case {{I}} < len({{DATA}}):
			%[6]s = {{DATA}}[{{I}}]
			%[7]s = {{KEY}}
			%[6]s ^= %[7]s
			{{DATA}}[{{I}}] = %[6]s
			%[3]s
			{{I}}++
		default:
			%[4]s
		}
	}
}
`

	code := fmt.Sprintf(template,
		stg.generateRandomString(8),
		garbage[0],
		garbage[1],
		"// unreachable",
		storageDecl,
		dataAccess,
		keyAccess)

	for placeholder, varName := range vars {
		code = strings.ReplaceAll(code, "{{"+strings.ToUpper(placeholder)+"}}", varName)
	}

	return code
}

// GetAllVariants genera tutte le varianti possibili
func (stg *StubTemplateGenerator) GetAllVariants(count int) []*StubVariant {
	variants := make([]*StubVariant, count)
	for i := 0; i < count; i++ {
		variants[i] = stg.GenerateVariant(i)
	}
	return variants
}
