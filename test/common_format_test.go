package test

import (
	"strings"
	"testing"

	"gosstrip/common"
)

func TestCategorizeDetailsGroupsByContent(t *testing.T) {
	details := []common.OperationDetail{
		{Message: "Removed section .text", Count: 1},
		{Message: "Regex pattern matched 5 strings", Count: 5},
		{Message: "Updated metadata", Count: 1, IsRisky: true},
	}

	categories := common.CategorizeDetails(details)
	if len(categories) != 3 {
		t.Fatalf("expected 3 categories, got %d: %#v", len(categories), categories)
	}
	if len(categories["SECTIONS"]) != 1 {
		t.Fatalf("expected section category to include detail, got %#v", categories["SECTIONS"])
	}
	if len(categories["PATTERNS"]) != 1 {
		t.Fatalf("expected pattern category to include detail, got %#v", categories["PATTERNS"])
	}
	if len(categories["OTHER"]) != 1 {
		t.Fatalf("expected other category to include detail, got %#v", categories["OTHER"])
	}
}

func TestFormatOperationResultPrintsCategorizedDetails(t *testing.T) {
	details := []common.OperationDetail{
		{Message: "Stripped section .debug_info", Count: 1},
		{Message: "Regex match: UPX", Count: 1},
	}
	categories := map[string][]common.OperationDetail{
		"Sections": {details[0]},
		"Patterns": {details[1]},
	}

	output := common.FormatOperationResult("Summary", nil, categories)
	if !strings.Contains(output, "Summary") {
		t.Fatalf("expected output to include title, got %q", output)
	}
	if !strings.Contains(output, "📦 SECTIONS") {
		t.Fatalf("expected sections heading, got %q", output)
	}
	if !strings.Contains(output, "🔍 PATTERNS") {
		t.Fatalf("expected pattern heading, got %q", output)
	}
	if !strings.Contains(output, "Stripped section .debug_info") {
		t.Fatalf("expected detail text, got %q", output)
	}
}

func TestFormatOperationResultHandlesPlainDetails(t *testing.T) {
	details := []common.OperationDetail{{Message: "Performed quick analysis", IsRisky: true}}
	output := common.FormatOperationResult("Quick Scan", details, nil)
	if !strings.Contains(output, "Quick Scan") {
		t.Fatalf("expected title in output, got %q", output)
	}
	if !strings.Contains(output, "⚠️ Performed quick analysis") {
		t.Fatalf("expected risky prefix, got %q", output)
	}
}
