package common

import "fmt"

// OperationResult represents the result of an operation with detailed information
type OperationResult struct {
	Applied bool
	Message string
	Count   int // Number of items affected (sections stripped, names obfuscated, etc.)
}

// NewSkipped creates a result for skipped operations
func NewSkipped(reason string) *OperationResult {
	return &OperationResult{
		Applied: false,
		Message: reason,
		Count:   0,
	}
}

// NewApplied creates a result for applied operations
func NewApplied(message string, count int) *OperationResult {
	return &OperationResult{
		Applied: true,
		Message: message,
		Count:   count,
	}
}

// String returns a human-readable representation
func (r *OperationResult) String() string {
	if r.Applied {
		if r.Count > 0 {
			return fmt.Sprintf("APPLIED (%s, %d items)", r.Message, r.Count)
		}
		return fmt.Sprintf("APPLIED (%s)", r.Message)
	}
	return fmt.Sprintf("SKIPPED (%s)", r.Message)
}
