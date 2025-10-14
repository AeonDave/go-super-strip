package pack

import (
	"fmt"
	"strings"
)

// PackConfig rappresenta la configurazione per il packing
type PackConfig struct {
	// Compressione
	CompressionAlgorithm string // "xz", "lzma", "none"
	CompressionLevel     int    // 0-9 (0=veloce, 9=massima compressione)

	// Cifratura
	EncryptionAlgorithm string // "xor", "aes-256-gcm", "chacha20", "none"
	EncryptionKey       []byte // Chiave custom (se vuota, viene generata random)

	// Polimorfismo
	PolymorphicStub     bool    // Abilita stub polimorfico
	JunkCodeDensity     float64 // 0.0-1.0 (densità di junk code)
	RegisterPermutation bool    // Permuta registri assembly
	ControlFlowMutation bool    // Muta control flow
	InstructionSubst    bool    // Sostituisce istruzioni equivalenti

	// Padding e obfuscation
	RandomPadding  bool // Aggiunge padding casuale al payload
	PaddingSizeMin int  // Dimensione minima padding (bytes)
	PaddingSizeMax int  // Dimensione massima padding (bytes)

	// Execution mode
	InMemoryExecution bool // true=in-memory, false=file temporaneo
	CleanupTemp       bool // Rimuove file temporanei dopo esecuzione

	// Anti-analysis
	AntiDebug bool // Inserisce check anti-debug
	AntiVM    bool // Inserisce check anti-VM

	// Output
	OutputPath string // Path file packed (se vuoto, sovrascrive originale)
	Verbose    bool   // Output verboso
}

// DefaultConfig ritorna una configurazione di default
func DefaultConfig() *PackConfig {
	return &PackConfig{
		CompressionAlgorithm: "xz",
		CompressionLevel:     6,
		EncryptionAlgorithm:  "aes-256-gcm",
		PolymorphicStub:      true,
		JunkCodeDensity:      0.2,
		RegisterPermutation:  false,
		ControlFlowMutation:  false,
		InstructionSubst:     false,
		RandomPadding:        true,
		PaddingSizeMin:       512,
		PaddingSizeMax:       4096,
		InMemoryExecution:    false, // Default: file temporaneo (più compatibile)
		CleanupTemp:          true,
		AntiDebug:            false,
		AntiVM:               false,
		Verbose:              false,
	}
}

// ParseOptions parsea le opzioni dal formato -p=opt1=val1,opt2=val2
func ParseOptions(optString string) (*PackConfig, error) {
	config := DefaultConfig()

	if optString == "" {
		return config, nil
	}

	// Split per virgole
	opts := strings.Split(optString, ",")

	for _, opt := range opts {
		parts := strings.SplitN(opt, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid option format: %s (expected key=value)", opt)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if err := config.setOption(key, value); err != nil {
			return nil, fmt.Errorf("option %s: %w", key, err)
		}
	}

	return config, nil
}

func (c *PackConfig) setOption(key, value string) error {
	switch strings.ToLower(key) {
	case "compression", "comp":
		c.CompressionAlgorithm = value
	case "level":
		var level int
		if _, err := fmt.Sscanf(value, "%d", &level); err != nil {
			return fmt.Errorf("invalid compression level: %s", value)
		}
		if level < 0 || level > 9 {
			return fmt.Errorf("compression level must be 0-9, got %d", level)
		}
		c.CompressionLevel = level
	case "encryption", "encrypt", "encr":
		// Normalizza gli alias comuni
		switch strings.ToLower(value) {
		case "aes", "aes-gcm", "aes256":
			c.EncryptionAlgorithm = "aes-256-gcm"
		case "chacha", "chacha20poly1305":
			c.EncryptionAlgorithm = "chacha20"
		default:
			c.EncryptionAlgorithm = strings.ToLower(value)
		}
	case "polymorphic", "poly":
		c.PolymorphicStub = parseBool(value)
	case "junkdensity", "junk":
		var density float64
		if _, err := fmt.Sscanf(value, "%f", &density); err != nil {
			return fmt.Errorf("invalid junk density: %s", value)
		}
		if density < 0 || density > 1 {
			return fmt.Errorf("junk density must be 0.0-1.0, got %.2f", density)
		}
		c.JunkCodeDensity = density
	case "regperm":
		c.RegisterPermutation = parseBool(value)
	case "cfmutation":
		c.ControlFlowMutation = parseBool(value)
	case "instrsubst":
		c.InstructionSubst = parseBool(value)
	case "padding":
		c.RandomPadding = parseBool(value)
	case "inmemory", "inmem":
		c.InMemoryExecution = parseBool(value)
	case "cleanup":
		c.CleanupTemp = parseBool(value)
	case "antidebug":
		c.AntiDebug = parseBool(value)
	case "antivm":
		c.AntiVM = parseBool(value)
	case "verbose", "v":
		c.Verbose = parseBool(value)
	default:
		return fmt.Errorf("unknown option: %s", key)
	}

	return nil
}

// Validate valida la configurazione
func (c *PackConfig) Validate() error {
	// Valida algoritmo compressione
	validComp := map[string]bool{
		"xz": true, "lzma": true, "none": true,
	}
	if !validComp[c.CompressionAlgorithm] {
		return fmt.Errorf("invalid compression algorithm: %s (valid: xz, lzma, none)", c.CompressionAlgorithm)
	}

	// Valida livello compressione
	if c.CompressionLevel < 0 || c.CompressionLevel > 9 {
		return fmt.Errorf("compression level must be 0-9, got %d", c.CompressionLevel)
	}

	// Valida algoritmo cifratura
	validEnc := map[string]bool{
		"xor": true, "aes-256-gcm": true, "chacha20": true, "none": true,
	}
	if !validEnc[c.EncryptionAlgorithm] {
		return fmt.Errorf("invalid encryption algorithm: %s (valid: xor, aes-256-gcm, chacha20, none)", c.EncryptionAlgorithm)
	}

	// Valida densità junk code
	if c.JunkCodeDensity < 0 || c.JunkCodeDensity > 1 {
		return fmt.Errorf("junk code density must be 0.0-1.0, got %.2f", c.JunkCodeDensity)
	}

	// Valida padding
	if c.PaddingSizeMin > c.PaddingSizeMax {
		return fmt.Errorf("padding min (%d) cannot be greater than max (%d)", c.PaddingSizeMin, c.PaddingSizeMax)
	}

	return nil
}

// String ritorna una rappresentazione testuale della configurazione
func (c *PackConfig) String() string {
	var sb strings.Builder

	sb.WriteString("Pack Configuration:\n")
	sb.WriteString(fmt.Sprintf("  Compression: %s (level %d)\n", c.CompressionAlgorithm, c.CompressionLevel))
	sb.WriteString(fmt.Sprintf("  Encryption: %s\n", c.EncryptionAlgorithm))
	sb.WriteString(fmt.Sprintf("  Polymorphic: %t\n", c.PolymorphicStub))

	if c.PolymorphicStub {
		sb.WriteString(fmt.Sprintf("    - Junk density: %.2f\n", c.JunkCodeDensity))
		sb.WriteString(fmt.Sprintf("    - Register permutation: %t\n", c.RegisterPermutation))
		sb.WriteString(fmt.Sprintf("    - Control flow mutation: %t\n", c.ControlFlowMutation))
		sb.WriteString(fmt.Sprintf("    - Instruction substitution: %t\n", c.InstructionSubst))
	}

	sb.WriteString(fmt.Sprintf("  Random padding: %t", c.RandomPadding))
	if c.RandomPadding {
		sb.WriteString(fmt.Sprintf(" (%d-%d bytes)", c.PaddingSizeMin, c.PaddingSizeMax))
	}
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("  In-memory execution: %t\n", c.InMemoryExecution))
	sb.WriteString(fmt.Sprintf("  Anti-debug: %t\n", c.AntiDebug))
	sb.WriteString(fmt.Sprintf("  Anti-VM: %t\n", c.AntiVM))

	return sb.String()
}
