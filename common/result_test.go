package common

import (
	"strings"
	"testing"
)

func TestNewSkipped(t *testing.T) {
	reason := "operation not applicable"
	result := NewSkipped(reason)

	if result.Applied {
		t.Error("expected Applied to be false for skipped operation")
	}
	if result.Message != reason {
		t.Errorf("expected Message %q, got %q", reason, result.Message)
	}
	if result.Count != 0 {
		t.Errorf("expected Count to be 0, got %d", result.Count)
	}
	if len(result.Details) != 0 {
		t.Errorf("expected empty Details, got %d items", len(result.Details))
	}
}

func TestNewApplied(t *testing.T) {
	message := "stripped 5 sections"
	count := 5
	result := NewApplied(message, count)

	if !result.Applied {
		t.Error("expected Applied to be true")
	}
	if result.Message != message {
		t.Errorf("expected Message %q, got %q", message, result.Message)
	}
	if result.Count != count {
		t.Errorf("expected Count %d, got %d", count, result.Count)
	}
	if len(result.Details) != 0 {
		t.Errorf("expected empty Details, got %d items", len(result.Details))
	}
}

func TestAddDetail(t *testing.T) {
	result := NewApplied("test operation", 1)

	result.AddDetail("removed .debug_info", 1, false)
	result.AddDetail("removed .symtab", 1, true)

	if len(result.Details) != 2 {
		t.Fatalf("expected 2 details, got %d", len(result.Details))
	}

	if result.Details[0].Message != "removed .debug_info" {
		t.Errorf("unexpected first detail message: %q", result.Details[0].Message)
	}
	if result.Details[0].Count != 1 {
		t.Errorf("expected first detail count 1, got %d", result.Details[0].Count)
	}
	if result.Details[0].IsRisky {
		t.Error("expected first detail to not be risky")
	}

	if result.Details[1].Message != "removed .symtab" {
		t.Errorf("unexpected second detail message: %q", result.Details[1].Message)
	}
	if result.Details[1].Count != 1 {
		t.Errorf("expected second detail count 1, got %d", result.Details[1].Count)
	}
	if !result.Details[1].IsRisky {
		t.Error("expected second detail to be risky")
	}
}

func TestSetCategory(t *testing.T) {
	result := NewApplied("test", 1)
	category := "stripping"

	result.SetCategory(category)

	if result.Category != category {
		t.Errorf("expected Category %q, got %q", category, result.Category)
	}
}

func TestFormatDetails_NoDetails(t *testing.T) {
	result := NewApplied("operation completed", 3)
	formatted := result.FormatDetails()

	if formatted != result.Message {
		t.Errorf("expected formatted output to be message when no details, got %q", formatted)
	}
}

func TestFormatDetails_Skipped(t *testing.T) {
	result := NewSkipped("not applicable")
	formatted := result.FormatDetails()

	if formatted != result.Message {
		t.Errorf("expected formatted output to be message for skipped, got %q", formatted)
	}
}

func TestFormatDetails_WithDetails(t *testing.T) {
	result := NewApplied("stripped sections", 2)
	result.AddDetail("removed .debug", 1, false)
	result.AddDetail("removed .symtab", 1, true)

	formatted := result.FormatDetails()

	// Should contain the main message and details
	if !strings.Contains(formatted, "stripped sections") {
		t.Error("expected formatted output to contain main message")
	}
}

func TestString_Applied_WithCount(t *testing.T) {
	result := NewApplied("sections removed", 5)
	str := result.String()

	expected := "APPLIED (sections removed, 5 items)"
	if str != expected {
		t.Errorf("expected %q, got %q", expected, str)
	}
}

func TestString_Applied_NoCount(t *testing.T) {
	result := NewApplied("operation completed", 0)
	str := result.String()

	expected := "APPLIED (operation completed)"
	if str != expected {
		t.Errorf("expected %q, got %q", expected, str)
	}
}

func TestString_Skipped(t *testing.T) {
	result := NewSkipped("no sections to strip")
	str := result.String()

	expected := "SKIPPED (no sections to strip)"
	if str != expected {
		t.Errorf("expected %q, got %q", expected, str)
	}
}

func TestOperationResult_MultipleOperations(t *testing.T) {
	// Test a realistic scenario with multiple details
	result := NewApplied("binary stripped", 10)
	result.SetCategory("stripping")
	result.AddDetail("removed .debug_info (1234 bytes)", 1, false)
	result.AddDetail("removed .debug_line (567 bytes)", 1, false)
	result.AddDetail("removed .symtab (890 bytes)", 1, false)
	result.AddDetail("removed .strtab (345 bytes)", 1, false)
	result.AddDetail("zeroed .comment section", 1, false)
	result.AddDetail("removed .note.* sections", 5, false)

	if !result.Applied {
		t.Error("expected operation to be applied")
	}
	if result.Count != 10 {
		t.Errorf("expected count 10, got %d", result.Count)
	}
	if len(result.Details) != 6 {
		t.Errorf("expected 6 details, got %d", len(result.Details))
	}
	if result.Category != "stripping" {
		t.Errorf("expected category 'stripping', got %q", result.Category)
	}

	str := result.String()
	if !strings.Contains(str, "APPLIED") {
		t.Error("expected String() to contain APPLIED")
	}
	if !strings.Contains(str, "10 items") {
		t.Error("expected String() to contain item count")
	}
}
