package pack

import (
	"fmt"
)

// Packer è l'interfaccia comune per tutti i packer (ELF/PE)
type Packer interface {
	// Pack comprime e cifra l'eseguibile
	Pack(inputPath string, config *PackConfig) (*PackResult, error)

	// GetFileType ritorna il tipo di file ("ELF" o "PE")
	GetFileType() string
}

// PackResult contiene i risultati del packing
type PackResult struct {
	OriginalSize     int64
	PackedSize       int64
	CompressionRatio float64
	OriginalHash     [32]byte
	PackedHash       [32]byte
	StubHash         [32]byte
	Applied          bool
	Message          string
	Details          []string
}

// NewPackResult crea un nuovo risultato di packing
func NewPackResult(originalSize, packedSize int64, originalHash, packedHash, stubHash [32]byte) *PackResult {
	var ratio float64
	var message string

	if packedSize <= originalSize {
		// File ridotto: mostra percentuale di compressione
		ratio = float64(packedSize) / float64(originalSize) * 100.0
		message = fmt.Sprintf("Packed successfully: %d -> %d bytes (%.1f%% of original)", originalSize, packedSize, ratio)
	} else {
		// File aumentato: mostra quanto è aumentato
		increase := packedSize - originalSize
		ratio = float64(increase) / float64(originalSize) * 100.0
		message = fmt.Sprintf("Packed successfully: %d -> %d bytes (+%d bytes, +%.1f%%)", originalSize, packedSize, increase, ratio)
	}

	return &PackResult{
		OriginalSize:     originalSize,
		PackedSize:       packedSize,
		CompressionRatio: ratio,
		OriginalHash:     originalHash,
		PackedHash:       packedHash,
		StubHash:         stubHash,
		Applied:          true,
		Message:          message,
	}
}

// AddDetail aggiunge un dettaglio al risultato
func (r *PackResult) AddDetail(detail string) {
	r.Details = append(r.Details, detail)
}

// String ritorna una rappresentazione testuale del risultato
func (r *PackResult) String() string {
	if !r.Applied {
		return fmt.Sprintf("❌ Packing failed: %s", r.Message)
	}

	result := fmt.Sprintf("✅ %s\n", r.Message)
	result += fmt.Sprintf("   Original hash: %x\n", r.OriginalHash[:8])
	result += fmt.Sprintf("   Packed hash:   %x\n", r.PackedHash[:8])
	result += fmt.Sprintf("   Stub hash:     %x\n", r.StubHash[:8])

	if len(r.Details) > 0 {
		result += "\n   Details:\n"
		for _, detail := range r.Details {
			result += fmt.Sprintf("     • %s\n", detail)
		}
	}

	return result
}

// PayloadMetadata contiene i metadata del payload compresso/cifrato
type PayloadMetadata struct {
	OriginalSize    uint64
	CompressedSize  uint64
	EncryptedSize   uint64
	CompressionAlgo string
	EncryptionAlgo  string
	EncryptionKey   []byte
	EncryptionNonce []byte
	PaddingOffsets  []int
	Checksum        [32]byte
}

// PolymorphicStub rappresenta uno stub polimorfico generato
type PolymorphicStub struct {
	Code             []byte
	EntryPointOffset int
	PayloadOffset    int
	MetadataOffset   int
	Hash             [32]byte
	Techniques       []string // Tecniche applicate
}

// StubTemplate è il template base per lo stub
type StubTemplate struct {
	Name              string
	TargetArch        string // "amd64", "386", "arm64"
	TargetOS          string // "linux", "windows"
	BaseCode          []byte
	PlaceholderOffset map[string]int // Offset per placeholder nel codice
}
