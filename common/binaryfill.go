package common

import "fmt"

// FillRegion overwrites a byte range with either zeroes or random data.
// It validates bounds before applying the fill and returns an error if the
// range would exceed the provided buffer.
func FillRegion(buffer []byte, offset int64, size int, useRandom bool) error {
	if size <= 0 {
		return nil
	}
	if offset < 0 {
		return fmt.Errorf("invalid offset: %d", offset)
	}
	end := offset + int64(size)
	if end > int64(len(buffer)) {
		return fmt.Errorf("write beyond buffer: offset=%d size=%d len=%d", offset, size, len(buffer))
	}
	region := buffer[offset:end]
	if useRandom {
		if err := RandomFillData(region); err != nil {
			return fmt.Errorf("failed to fill with random bytes: %w", err)
		}
	} else {
		ZeroFillData(region)
	}
	return nil
}
