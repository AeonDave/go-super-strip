package pack

import (
	"bytes"
	"testing"
)

func TestCipherADFL(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		seed byte
	}{
		{
			name: "small data",
			data: []byte{0x41, 0x42, 0x43, 0x44},
			seed: 0x55,
		},
		{
			name: "larger data",
			data: bytes.Repeat([]byte("TEST"), 10),
			seed: 0xAA,
		},
		{
			name: "binary data",
			data: []byte{0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE},
			seed: 0x12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := make([]byte, len(tt.data))
			copy(original, tt.data)

			// Cifra
			ciphered := CipherADFL(tt.data, tt.seed)

			// Verifica che sia cambiato
			if bytes.Equal(ciphered, original) {
				t.Error("Ciphered data should differ from original")
			}

			// Per ADFL, la decifratura richiede l'algoritmo inverso
			// In questo test verifichiamo solo che la cifratura modifichi i dati
			// La decifratura viene testata nella trasformazione completa
			t.Logf("Original:  %x", original)
			t.Logf("Ciphered:  %x", ciphered)
		})
	}
}

func TestSGNSchemaCipher(t *testing.T) {
	sgn := NewSGNPolymorphicEngine(64)

	tests := []struct {
		name       string
		data       []byte
		schemaSize int
	}{
		{
			name:       "single block",
			data:       bytes.Repeat([]byte{0x41}, 64),
			schemaSize: 4,
		},
		{
			name:       "multiple blocks",
			data:       bytes.Repeat([]byte{0x55}, 128),
			schemaSize: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := make([]byte, len(tt.data))
			copy(original, tt.data)

			// Genera schema
			schema := sgn.NewCipherSchema(tt.schemaSize)

			// Applica schema
			ciphered := sgn.SchemaCipher(tt.data, 0, schema)

			// Verifica che sia cambiato (almeno in parte)
			if bytes.Equal(ciphered, original) {
				t.Error("Schema cipher should modify data")
			}

			// Verifica lunghezza invariata
			if len(ciphered) != len(original) {
				t.Errorf("Length changed: got %d, want %d", len(ciphered), len(original))
			}
		})
	}
}

func TestNewCipherSchema(t *testing.T) {
	sgn := NewSGNPolymorphicEngine(64)

	sizes := []int{1, 4, 8, 16}

	for _, size := range sizes {
		t.Run("schema_size_"+string(rune(size+'0')), func(t *testing.T) {
			schema := sgn.NewCipherSchema(size)

			if len(schema) != size {
				t.Errorf("Schema size: got %d, want %d", len(schema), size)
			}

			// Verifica che ogni elemento abbia operando valido
			for i, s := range schema {
				if s.OP == "" {
					t.Errorf("Schema[%d] has empty operand", i)
				}

				// NOT non deve avere key, altri sì
				if s.OP == "NOT" {
					if s.Key != nil {
						t.Errorf("Schema[%d] NOT should have nil key", i)
					}
				} else {
					if len(s.Key) != 4 {
						t.Errorf("Schema[%d] key length: got %d, want 4", i, len(s.Key))
					}
				}
			}
		})
	}
}

func TestGenerateGarbageInstructions(t *testing.T) {
	sgn := NewSGNPolymorphicEngine(64)

	for i := 0; i < 10; i++ {
		garbage, err := sgn.GenerateGarbageInstructions()
		if err != nil {
			t.Fatalf("Failed to generate garbage: %v", err)
		}

		if len(garbage) == 0 {
			t.Error("Garbage instructions should not be empty")
		}

		if len(garbage) > sgn.obfuscationLimit*2 {
			t.Errorf("Garbage too large: %d bytes (limit: %d)", len(garbage), sgn.obfuscationLimit*2)
		}
	}
}

func TestGenerateJumpOver(t *testing.T) {
	sgn := NewSGNPolymorphicEngine(64)

	sizes := []int{4, 8, 16, 32, 64, 100, 150}

	for _, size := range sizes {
		jumpOver := sgn.GenerateJumpOver(size)

		// Verifica che inizi con EB (short jump)
		if jumpOver[0] != 0xEB {
			t.Errorf("Jump should start with 0xEB, got 0x%02x", jumpOver[0])
		}

		// Se size > 127, dovrebbe essere capped a 127
		expectedSize := size
		if size > 127 {
			expectedSize = 127
		}

		// Lunghezza totale = 2 (JMP instruction) + garbage size
		expectedLen := 2 + expectedSize
		if len(jumpOver) != expectedLen {
			t.Errorf("Jump over length: got %d, want %d", len(jumpOver), expectedLen)
		}
	}
}

func TestGenerateGarbageAssembly(t *testing.T) {
	sgn := NewSGNPolymorphicEngine(64)

	// Genera più volte per testare randomness
	generated := make(map[string]bool)
	for i := 0; i < 20; i++ {
		asm := sgn.GenerateGarbageAssembly()
		generated[asm] = true
	}

	// Dovremmo avere almeno qualche variazione
	if len(generated) < 2 {
		t.Error("Garbage assembly should have some randomness")
	}
}

func TestGenerateConditionalJump(t *testing.T) {
	sgn := NewSGNPolymorphicEngine(64)

	for i := 0; i < 5; i++ {
		jump := sgn.GenerateConditionalJump()

		if jump == "" {
			t.Error("Conditional jump should not be empty")
		}

		// Dovrebbe contenere TEST e un mnemonic di jump
		if !contains(jump, "TEST") {
			t.Error("Conditional jump should contain TEST")
		}
	}
}

func TestGenerateFunctionFrame(t *testing.T) {
	tests := []struct {
		name string
		arch int
		bp   string
		sp   string
	}{
		{
			name: "32-bit",
			arch: 32,
			bp:   "EBP",
			sp:   "ESP",
		},
		{
			name: "64-bit",
			arch: 64,
			bp:   "RBP",
			sp:   "RSP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sgn := NewSGNPolymorphicEngine(tt.arch)
			frame := sgn.GenerateFunctionFrame()

			// Verifica presenza di PUSH/POP/MOV
			if !contains(frame, "PUSH") {
				t.Error("Function frame should contain PUSH")
			}
			if !contains(frame, "POP") {
				t.Error("Function frame should contain POP")
			}
			if !contains(frame, "MOV") {
				t.Error("Function frame should contain MOV")
			}

			// Verifica presenza registri corretti
			if !contains(frame, tt.bp) {
				t.Errorf("Function frame should contain %s", tt.bp)
			}
			if !contains(frame, tt.sp) {
				t.Errorf("Function frame should contain %s", tt.sp)
			}
		})
	}
}

func TestApplyPolymorphicTransform(t *testing.T) {
	sgn := NewSGNPolymorphicEngine(64)

	// Dati di test
	original := bytes.Repeat([]byte("PAYLOAD_DATA"), 20)

	transformed, err := sgn.ApplyPolymorphicTransform(original)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	// Verifica che sia cambiato
	if bytes.Equal(transformed, original) {
		t.Error("Transformed data should differ from original")
	}

	// Verifica che sia più lungo (garbage aggiunto)
	if len(transformed) <= len(original) {
		t.Error("Transformed data should be longer (garbage added)")
	}
}

func TestApplySGNToELF(t *testing.T) {
	// Mock ELF data (ELF header + padding)
	elfData := make([]byte, 1024)
	copy(elfData[0:4], []byte{0x7f, 'E', 'L', 'F'}) // ELF magic
	elfData[4] = 2                                  // 64-bit
	elfData[5] = 1                                  // little-endian

	config := &PackConfig{
		PolymorphicStub: true,
		Verbose:         false,
	}

	result, techniques, err := ApplySGNToELF(elfData, config)
	if err != nil {
		t.Fatalf("ApplySGNToELF failed: %v", err)
	}

	// Verifica che le tecniche siano state applicate
	if len(techniques) == 0 {
		t.Error("No techniques applied")
	}

	// Verifica che il magic ELF sia ancora intatto
	if !bytes.Equal(result[0:4], []byte{0x7f, 'E', 'L', 'F'}) {
		t.Error("ELF magic was corrupted")
	}

	// Verifica che qualcosa sia cambiato
	if bytes.Equal(result, elfData) {
		t.Error("ELF data should be modified")
	}
}

func TestApplySGNToPE(t *testing.T) {
	// Mock PE data (DOS header + padding)
	peData := make([]byte, 1024)
	copy(peData[0:2], []byte{'M', 'Z'}) // DOS magic

	config := &PackConfig{
		PolymorphicStub: true,
		Verbose:         false,
	}

	result, techniques, err := ApplySGNToPE(peData, config)
	if err != nil {
		t.Fatalf("ApplySGNToPE failed: %v", err)
	}

	// Verifica tecniche applicate
	if len(techniques) == 0 {
		t.Error("No techniques applied")
	}

	// Verifica che il magic MZ sia ancora intatto
	if !bytes.Equal(result[0:2], []byte{'M', 'Z'}) {
		t.Error("PE magic was corrupted")
	}
}

func TestFindPaddingZones(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		minSize  int
		expected int // numero di zone attese
	}{
		{
			name:     "no padding",
			data:     bytes.Repeat([]byte{0xFF}, 100),
			minSize:  10,
			expected: 0,
		},
		{
			name:     "single padding zone",
			data:     append(append([]byte{0xFF, 0xFF}, bytes.Repeat([]byte{0x00}, 50)...), []byte{0xFF, 0xFF}...),
			minSize:  10,
			expected: 1,
		},
		{
			name: "multiple zones",
			data: append(append(append(append(
				bytes.Repeat([]byte{0x00}, 20),
				[]byte{0xFF, 0xFF}...),
				bytes.Repeat([]byte{0xCC}, 30)...),
				[]byte{0xFF}...),
				bytes.Repeat([]byte{0x00}, 40)...),
			minSize:  15,
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zones := findPaddingZones(tt.data, tt.minSize)

			if len(zones) != tt.expected {
				t.Errorf("Found %d zones, expected %d", len(zones), tt.expected)
			}

			// Verifica che ogni zona sia >= minSize
			for i, zone := range zones {
				size := zone.end - zone.start
				if size < tt.minSize {
					t.Errorf("Zone %d too small: %d bytes (min: %d)", i, size, tt.minSize)
				}
			}
		})
	}
}

func TestGetSchemaDescription(t *testing.T) {
	sgn := NewSGNPolymorphicEngine(64)
	schema := sgn.NewCipherSchema(5)

	desc := GetSchemaDescription(schema)

	if desc == "" {
		t.Error("Schema description should not be empty")
	}

	// Verifica che contenga informazioni sulle operazioni
	if !contains(desc, "Cipher Schema") {
		t.Error("Description should contain 'Cipher Schema'")
	}
}

func TestSGNPolymorphicEngine_GetRandomRegister(t *testing.T) {
	tests := []struct {
		arch int
		name string
	}{
		{32, "32-bit"},
		{64, "64-bit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sgn := NewSGNPolymorphicEngine(tt.arch)

			// Genera più registri e verifica che siano validi
			registers := make(map[string]bool)
			for i := 0; i < 20; i++ {
				reg := sgn.getRandomRegister()
				if reg == "" {
					t.Error("Register should not be empty")
				}
				registers[reg] = true
			}

			// Dovremmo avere almeno 3 registri diversi
			if len(registers) < 3 {
				t.Error("Should generate variety of registers")
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
