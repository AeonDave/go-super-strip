package common

import (
	"fmt"
	"strings"
)

// OperationDetail represents a single detail of an operation result
type OperationDetail struct {
	Message string
	Count   int
	IsRisky bool
}

// FormatOperationResult formats an operation result with consistent styling
func FormatOperationResult(title string, details []OperationDetail, categories map[string][]OperationDetail) string {
	if len(details) == 0 && len(categories) == 0 {
		return "No operations performed"
	}

	var result strings.Builder
	result.WriteString(title)

	// Format categorized details
	if len(categories) > 0 {
		result.WriteString("\n")
		for category, categoryDetails := range categories {
			if len(categoryDetails) == 0 {
				continue
			}

			var emoji string
			switch {
			case strings.Contains(strings.ToLower(category), "section"):
				emoji = "📦"
			case strings.Contains(strings.ToLower(category), "regex") ||
				strings.Contains(strings.ToLower(category), "pattern"):
				emoji = "🔍"
			case strings.Contains(strings.ToLower(category), "string"):
				emoji = "🔤"
			default:
				emoji = "🛠️"
			}

			result.WriteString(fmt.Sprintf("%s %s:\n", emoji, strings.ToUpper(category)))
			for _, detail := range categoryDetails {
				prefix := "   ✓ "
				if detail.IsRisky {
					prefix = "   ⚠️ "
				}
				result.WriteString(prefix + detail.Message + "\n")
			}
		}
	}

	// Format uncategorized details
	if len(details) > 0 && len(categories) == 0 {
		for _, detail := range details {
			prefix := "✓ "
			if detail.IsRisky {
				prefix = "⚠️ "
			}
			result.WriteString("\n" + prefix + detail.Message)
		}
	}

	return strings.TrimSuffix(result.String(), "\n")
}

// CategorizeDetails helps categorize operation details
func CategorizeDetails(details []OperationDetail) map[string][]OperationDetail {
	categories := map[string][]OperationDetail{
		"SECTIONS": {},
		"PATTERNS": {},
		"OTHER":    {},
	}

	for _, detail := range details {
		msg := strings.ToLower(detail.Message)
		switch {
		case strings.Contains(msg, "section") || strings.Contains(msg, "stripped"):
			categories["SECTIONS"] = append(categories["SECTIONS"], detail)
		case strings.Contains(msg, "regex") || strings.Contains(msg, "pattern") ||
			strings.Contains(msg, "match"):
			categories["PATTERNS"] = append(categories["PATTERNS"], detail)
		default:
			categories["OTHER"] = append(categories["OTHER"], detail)
		}
	}

	// Remove empty categories
	for category, details := range categories {
		if len(details) == 0 {
			delete(categories, category)
		}
	}

	return categories
}
