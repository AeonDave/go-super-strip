package common

import "fmt"

// OperationResult represents the result of an operation with detailed information
type OperationResult struct {
	Applied  bool
	Message  string
	Count    int // Number of items affected (sections stripped, names obfuscated, etc.)
	Details  []OperationDetail
	Category string // Optional category for grouping in output
}

// NewSkipped creates a result for skipped operations
func NewSkipped(reason string) *OperationResult {
	return &OperationResult{
		Applied: false,
		Message: reason,
		Count:   0,
		Details: []OperationDetail{},
	}
}

// NewApplied creates a result for applied operations
func NewApplied(message string, count int) *OperationResult {
	return &OperationResult{
		Applied: true,
		Message: message,
		Count:   count,
		Details: []OperationDetail{},
	}
}

// AddDetail adds a detail to the operation result
func (r *OperationResult) AddDetail(message string, count int, isRisky bool) {
	r.Details = append(r.Details, OperationDetail{
		Message: message,
		Count:   count,
		IsRisky: isRisky,
	})
}

// SetCategory sets the category for the operation result
func (r *OperationResult) SetCategory(category string) {
	r.Category = category
}

// FormatDetails formats the details of the operation result
func (r *OperationResult) FormatDetails() string {
	if !r.Applied {
		return r.Message
	}

	// If no details are provided, just return the message
	if len(r.Details) == 0 {
		return r.Message
	}

	// Group details by category if not already categorized
	categories := CategorizeDetails(r.Details)
	return FormatOperationResult(r.Message, r.Details, categories)
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
