package pack

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/ulikunitz/xz"
)

// CompressPayload comprime il payload secondo la configurazione
func CompressPayload(data []byte, config *PackConfig) ([]byte, error) {
	switch config.CompressionAlgorithm {
	case "xz":
		return compressXZ(data, config.CompressionLevel)
	case "lzma":
		return compressLZMA(data, config.CompressionLevel)
	case "zlib":
		return compressZlib(data, config.CompressionLevel)
	case "none":
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", config.CompressionAlgorithm)
	}
}

// DecompressPayload decomprime il payload
func DecompressPayload(data []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "xz":
		return decompressXZ(data)
	case "lzma":
		return decompressLZMA(data)
	case "zlib":
		return decompressZlib(data)
	case "none":
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}
}

// compressXZ comprime con XZ/LZMA
func compressXZ(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer

	// Configura writer XZ
	config := xz.WriterConfig{
		DictCap: 1 << uint(20+level), // 1MB - 512MB based on level
	}

	w, err := config.NewWriter(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create xz writer: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close xz writer: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressXZ decomprime XZ/LZMA
func decompressXZ(data []byte) ([]byte, error) {
	r, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create xz reader: %w", err)
	}

	decompressed, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	return decompressed, nil
}

// compressLZMA comprime con LZMA (formato LZMA stream, non XZ container)
func compressLZMA(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer

	// LZMA writer configuration (raw LZMA stream)
	config := xz.WriterConfig{
		DictCap: 1 << uint(20+level), // 1MB - 512MB based on level
	}

	// Per LZMA puro, usiamo lo stesso writer ma con formato diverso
	// In produzione, si userebbe lzma.Writer specifico se disponibile
	w, err := config.NewWriter(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create lzma writer: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close lzma writer: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressLZMA decomprime LZMA puro
func decompressLZMA(data []byte) ([]byte, error) {
	// Per ora usiamo lo stesso decompressor di XZ
	// In produzione, si userebbe lzma.Reader specifico se disponibile
	r, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create lzma reader: %w", err)
	}

	decompressed, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	return decompressed, nil
}

// compressZlib comprime con zlib (fallback se xz non disponibile)
func compressZlib(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer

	// Mappa level 0-9 a zlib levels
	zlibLevel := map[int]int{
		0: zlib.NoCompression,
		1: zlib.BestSpeed,
		9: zlib.BestCompression,
	}

	compressionLevel := zlib.DefaultCompression
	if lvl, ok := zlibLevel[level]; ok {
		compressionLevel = lvl
	} else if level >= 2 && level <= 8 {
		compressionLevel = level - 1
	}

	w, err := zlib.NewWriterLevel(&buf, compressionLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib writer: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zlib writer: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressZlib decomprime zlib
func decompressZlib(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer func(r io.ReadCloser) {
		_ = r.Close()
	}(r)

	decompressed, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	return decompressed, nil
}

// AddRandomPadding aggiunge padding casuale al payload
func AddRandomPadding(data []byte, config *PackConfig) ([]byte, []int, error) {
	if !config.RandomPadding {
		return data, nil, nil
	}

	// Genera dimensione padding casuale
	paddingSize := config.PaddingSizeMin
	if config.PaddingSizeMax > config.PaddingSizeMin {
		paddingSize += randomInt(config.PaddingSizeMax - config.PaddingSizeMin)
	}

	// Genera padding casuale
	padding := randomBytes(paddingSize)

	// Inserisci padding in posizioni casuali
	// Per semplicità, aggiungiamo all'inizio e alla fine
	// In produzione, si potrebbero inserire chunk random nel mezzo

	paddingOffsets := []int{0, len(data)}

	result := make([]byte, 0, len(data)+len(padding))
	result = append(result, padding[:paddingSize/2]...)
	result = append(result, data...)
	result = append(result, padding[paddingSize/2:]...)

	return result, paddingOffsets, nil
}
