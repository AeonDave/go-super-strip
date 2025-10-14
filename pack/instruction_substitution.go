package pack

import (
	"fmt"
	mathrand "math/rand"
	"strings"
)

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
		// Zero initialization
		{
			Original: "{{VAR}} := 0",
			Alternatives: []string{
				"{{VAR}} := 1 - 1",
				"{{VAR}} := 2 * 0",
				"{{VAR}} := 0x00",
				"{{VAR}}, _ := 0, 1",
				"{{VAR}} = ^0 + 1",
				"{{VAR}} := (5 - 5)",
			},
			Description: "Zero initialization variants",
		},
		// Increment
		{
			Original: "{{VAR}}++",
			Alternatives: []string{
				"{{VAR}} = {{VAR}} + 1",
				"{{VAR}} += 1",
				"{{VAR}} = {{VAR}} | 1; if {{VAR}} & 1 == 1 { {{VAR}}++ }",
			},
			Description: "Increment variants",
		},
		// Decrement
		{
			Original: "{{VAR}}--",
			Alternatives: []string{
				"{{VAR}} = {{VAR}} - 1",
				"{{VAR}} -= 1",
				"{{VAR}} = {{VAR}} + ^0",
			},
			Description: "Decrement variants",
		},
		// XOR assignment
		{
			Original: "{{VAR}} ^= {{KEY}}",
			Alternatives: []string{
				"{{VAR}} = {{VAR}} ^ {{KEY}}",
				"{{TEMP}} := {{VAR}}; {{VAR}} = {{TEMP}} ^ {{KEY}}",
				"{{VAR}} = ({{VAR}} | {{KEY}}) & ^({{VAR}} & {{KEY}})",
			},
			Description: "XOR operation variants",
		},
		// Addition
		{
			Original: "{{VAR}} += {{VAL}}",
			Alternatives: []string{
				"{{VAR}} = {{VAR}} + {{VAL}}",
				"for i := 0; i < {{VAL}}; i++ { {{VAR}}++ }",
				"{{TEMP}} := {{VAL}}; {{VAR}} = {{VAR}} + {{TEMP}}",
			},
			Description: "Addition variants",
		},
		// Subtraction
		{
			Original: "{{VAR}} -= {{VAL}}",
			Alternatives: []string{
				"{{VAR}} = {{VAR}} - {{VAL}}",
				"{{VAR}} += (^{{VAL}} + 1)",
				"{{TEMP}} := {{VAL}}; {{VAR}} = {{VAR}} - {{TEMP}}",
			},
			Description: "Subtraction variants",
		},
		// Byte conversion
		{
			Original: "{{VAR}} = byte({{EXPR}})",
			Alternatives: []string{
				"{{VAR}} = byte({{EXPR}} & 0xFF)",
				"{{VAR}} = byte({{EXPR}} % 256)",
				"{{TEMP}} := {{EXPR}}; {{VAR}} = byte({{TEMP}})",
			},
			Description: "Byte conversion variants",
		},
		// Modulo 256
		{
			Original: "{{EXPR}} % 256",
			Alternatives: []string{
				"{{EXPR}} & 0xFF",
				"{{EXPR}} & 255",
				"({{EXPR}} << 24) >> 24",
			},
			Description: "Modulo 256 variants",
		},
	}
}

// ApplySubstitution applica sostituzioni casuali al codice
func (ise *InstructionSubstitutionEngine) ApplySubstitution(code string, varName string) string {
	patterns := ise.GetAllPatterns()

	// Applica alcune sostituzioni casuali
	result := code

	for _, pattern := range patterns {
		if strings.Contains(result, pattern.Original) {
			// 50% chance di applicare la sostituzione
			if ise.rng.Intn(2) == 0 {
				alternative := pattern.Alternatives[ise.rng.Intn(len(pattern.Alternatives))]

				// Sostituisci placeholder con nome variabile reale
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
	styles := []string{
		// Style 1: standard for loop
		`for %s := %s; %s < %s; %s++ {
	%s
}`,
		// Style 2: for loop with condition
		`%s := %s
for %s < %s {
	%s
	%s++
}`,
		// Style 3: for range (se applicabile)
		`for %s := range make([]byte, %s - %s) {
	%s
}`,
	}

	style := styles[ise.rng.Intn(len(styles))]

	switch ise.rng.Intn(3) {
	case 0:
		return fmt.Sprintf(styles[0], loopVar, start, loopVar, end, loopVar, body)
	case 1:
		return fmt.Sprintf(styles[1], loopVar, start, loopVar, end, body, loopVar)
	case 2:
		// Style 3 è complicato, usiamo style 1
		return fmt.Sprintf(styles[0], loopVar, start, loopVar, end, loopVar, body)
	}

	return fmt.Sprintf(style, loopVar, start, end, body)
}

// GenerateConditional genera condizionali equivalenti
func (ise *InstructionSubstitutionEngine) GenerateConditional(condition, trueBlock, falseBlock string) string {
	styles := []string{
		// Style 1: if-else
		`if %s {
	%s
} else {
	%s
}`,
		// Style 2: switch
		`switch {
case %s:
	%s
default:
	%s
}`,
		// Style 3: negated if-else
		`if !(%s) {
	%s
} else {
	%s
}`,
	}

	style := styles[ise.rng.Intn(len(styles))]

	switch ise.rng.Intn(3) {
	case 0:
		return fmt.Sprintf(styles[0], condition, trueBlock, falseBlock)
	case 1:
		return fmt.Sprintf(styles[1], condition, trueBlock, falseBlock)
	case 2:
		return fmt.Sprintf(styles[2], condition, falseBlock, trueBlock)
	}

	return fmt.Sprintf(style, condition, trueBlock, falseBlock)
}

// GenerateStorageVariant genera varianti di storage per dati temporanei
func (ise *InstructionSubstitutionEngine) GenerateStorageVariant(varName string, dataType string) string {
	variants := []string{
		// Array
		fmt.Sprintf("var %s [1]%s", varName, dataType),
		// Slice
		fmt.Sprintf("%s := make([]%s, 1)", varName, dataType),
		// Pointer
		fmt.Sprintf("%s := new(%s)", varName, dataType),
		// Direct
		fmt.Sprintf("var %s %s", varName, dataType),
	}

	return variants[ise.rng.Intn(len(variants))]
}

// GenerateBlockCipherOps genera operazioni di cipher casuali
func (ise *InstructionSubstitutionEngine) GenerateBlockCipherOps(data, key string) string {
	ops := []string{
		// XOR only
		fmt.Sprintf("%s ^= %s", data, key),

		// XOR + ADD
		fmt.Sprintf("%s ^= %s\n\t%s = byte((int(%s) + int(%s)) %% 256)",
			data, key, key, data, key),

		// XOR + ROL
		fmt.Sprintf("%s ^= %s\n\t%s = (%s << 1) | (%s >> 7)",
			data, key, key, key, key),

		// ADD + XOR
		fmt.Sprintf("%s = byte((int(%s) + int(%s)) %% 256)\n\t%s ^= %s",
			data, data, key, data, key),

		// SUB + XOR
		fmt.Sprintf("%s = byte((int(%s) - int(%s) + 256) %% 256)\n\t%s ^= %s",
			data, data, key, data, key),

		// NOT + XOR
		fmt.Sprintf("%s = ^%s\n\t%s ^= %s",
			data, data, data, key),
	}

	return ops[ise.rng.Intn(len(ops))]
}
