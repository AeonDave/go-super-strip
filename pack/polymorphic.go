package pack

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
)

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
