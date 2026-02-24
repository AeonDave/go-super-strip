package pack

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// CompressPayload comprime il payload secondo la configurazione
func CompressPayload(data []byte, config *PackConfig) ([]byte, error) {
	switch config.CompressionAlgorithm {
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
	case "zlib":
		return decompressZlib(data)
	case "none":
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}
}

// compressZlib comprime con zlib.
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
