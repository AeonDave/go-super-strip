package common

import (
	"fmt"
	"strings"
)

// binaryCloser represents the minimal interface required to participate in wrapper helpers.
type binaryCloser interface {
	Close() error
}

// ProcessBinary centralizes the boilerplate used by PE/ELF wrappers: open the file,
// run the provided operation, and persist the result when it mutated the binary.
func ProcessBinary[T binaryCloser](
	filePath string,
	flags int,
	fileKind string,
	openFunc func(string, int) (T, error),
	saveFunc func(T) error,
	operation func(T) *OperationResult,
) *OperationResult {
	bin, err := openFunc(filePath, flags)
	if err != nil {
		return NewSkipped(fmt.Sprintf("Failed to read %s file: %v", strings.ToUpper(fileKind), err))
	}
	defer func() { _ = bin.Close() }()

	result := operation(bin)
	if result.Applied && saveFunc != nil {
		if err := saveFunc(bin); err != nil {
			return NewSkipped(fmt.Sprintf("Operation succeeded but failed to save %s file: %v", strings.ToUpper(fileKind), err))
		}
	}
	return result
}
