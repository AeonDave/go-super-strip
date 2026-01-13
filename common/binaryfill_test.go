package common

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Tests for binaryfill.go

func TestFillRegion_WithZeros(t *testing.T) {
	buffer := make([]byte, 100)
	for i := range buffer {
		buffer[i] = 0xFF
	}

	err := FillRegion(buffer, 10, 20, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that the region was zeroed
	for i := 10; i < 30; i++ {
		if buffer[i] != 0 {
			t.Errorf("expected buffer[%d] to be 0, got %d", i, buffer[i])
		}
	}

	// Check that surrounding bytes are unchanged
	for i := 0; i < 10; i++ {
		if buffer[i] != 0xFF {
			t.Errorf("expected buffer[%d] to be 0xFF, got %d", i, buffer[i])
		}
	}
	for i := 30; i < 100; i++ {
		if buffer[i] != 0xFF {
			t.Errorf("expected buffer[%d] to be 0xFF, got %d", i, buffer[i])
		}
	}
}

func TestFillRegion_WithRandom(t *testing.T) {
	buffer := make([]byte, 100)
	for i := range buffer {
		buffer[i] = 0x00
	}

	err := FillRegion(buffer, 10, 20, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that the region was modified (at least some bytes should be non-zero)
	nonZeroCount := 0
	for i := 10; i < 30; i++ {
		if buffer[i] != 0 {
			nonZeroCount++
		}
	}
	if nonZeroCount == 0 {
		t.Error("expected at least some random bytes to be non-zero")
	}

	// Check that surrounding bytes are unchanged
	for i := 0; i < 10; i++ {
		if buffer[i] != 0x00 {
			t.Errorf("expected buffer[%d] to be 0x00, got %d", i, buffer[i])
		}
	}
	for i := 30; i < 100; i++ {
		if buffer[i] != 0x00 {
			t.Errorf("expected buffer[%d] to be 0x00, got %d", i, buffer[i])
		}
	}
}

func TestFillRegion_ZeroSize(t *testing.T) {
	buffer := make([]byte, 100)
	original := make([]byte, 100)
	copy(original, buffer)

	err := FillRegion(buffer, 10, 0, false)
	if err != nil {
		t.Fatalf("unexpected error for zero size: %v", err)
	}

	// Buffer should be unchanged
	if !bytes.Equal(buffer, original) {
		t.Error("expected buffer to remain unchanged for zero size")
	}
}

func TestFillRegion_NegativeSize(t *testing.T) {
	buffer := make([]byte, 100)
	original := make([]byte, 100)
	copy(original, buffer)

	err := FillRegion(buffer, 10, -5, false)
	if err != nil {
		t.Fatalf("unexpected error for negative size: %v", err)
	}

	// Buffer should be unchanged
	if !bytes.Equal(buffer, original) {
		t.Error("expected buffer to remain unchanged for negative size")
	}
}

func TestFillRegion_NegativeOffset(t *testing.T) {
	buffer := make([]byte, 100)

	err := FillRegion(buffer, -10, 20, false)
	if err == nil {
		t.Fatal("expected error for negative offset")
	}
	if !strings.Contains(err.Error(), "invalid offset") {
		t.Errorf("expected error message to contain 'invalid offset', got %v", err)
	}
}

func TestFillRegion_BeyondBuffer(t *testing.T) {
	buffer := make([]byte, 100)

	err := FillRegion(buffer, 90, 20, false)
	if err == nil {
		t.Fatal("expected error for write beyond buffer")
	}
	if !strings.Contains(err.Error(), "write beyond buffer") {
		t.Errorf("expected error message to contain 'write beyond buffer', got %v", err)
	}
}

func TestFillRegion_ExactlyAtEnd(t *testing.T) {
	buffer := make([]byte, 100)
	for i := range buffer {
		buffer[i] = 0xFF
	}

	err := FillRegion(buffer, 90, 10, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that the last 10 bytes were zeroed
	for i := 90; i < 100; i++ {
		if buffer[i] != 0 {
			t.Errorf("expected buffer[%d] to be 0, got %d", i, buffer[i])
		}
	}
}

func TestFillRegion_FullBuffer(t *testing.T) {
	buffer := make([]byte, 50)
	for i := range buffer {
		buffer[i] = 0xAA
	}

	err := FillRegion(buffer, 0, 50, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that entire buffer was zeroed
	for i := range buffer {
		if buffer[i] != 0 {
			t.Errorf("expected buffer[%d] to be 0, got %d", i, buffer[i])
		}
	}
}

// Tests for stage_error.go

func TestStageError_Error_WithStage(t *testing.T) {
	baseErr := errors.New("file not found")
	stageErr := &StageError{
		Stage: "strip",
		Err:   baseErr,
	}

	expected := "strip: file not found"
	if stageErr.Error() != expected {
		t.Errorf("expected %q, got %q", expected, stageErr.Error())
	}
}

func TestStageError_Error_EmptyStage(t *testing.T) {
	baseErr := errors.New("operation failed")
	stageErr := &StageError{
		Stage: "",
		Err:   baseErr,
	}

	expected := "operation failed"
	if stageErr.Error() != expected {
		t.Errorf("expected %q, got %q", expected, stageErr.Error())
	}
}

func TestStageError_Unwrap(t *testing.T) {
	baseErr := errors.New("base error")
	stageErr := &StageError{
		Stage: "compact",
		Err:   baseErr,
	}

	unwrapped := stageErr.Unwrap()
	if unwrapped != baseErr {
		t.Errorf("expected Unwrap to return base error, got %v", unwrapped)
	}
}

func TestWrapStageError_WithError(t *testing.T) {
	baseErr := errors.New("test error")
	wrapped := WrapStageError("obfuscate", baseErr)

	if wrapped == nil {
		t.Fatal("expected non-nil wrapped error")
	}

	stageErr, ok := wrapped.(*StageError)
	if !ok {
		t.Fatalf("expected *StageError, got %T", wrapped)
	}

	if stageErr.Stage != "obfuscate" {
		t.Errorf("expected stage 'obfuscate', got %q", stageErr.Stage)
	}
	if stageErr.Err != baseErr {
		t.Errorf("expected wrapped error to be base error")
	}
}

func TestWrapStageError_WithNilError(t *testing.T) {
	wrapped := WrapStageError("test", nil)
	if wrapped != nil {
		t.Errorf("expected nil when wrapping nil error, got %v", wrapped)
	}
}

func TestStageError_ErrorsIs(t *testing.T) {
	baseErr := errors.New("base error")
	wrapped := WrapStageError("stage", baseErr)

	// Test that errors.Is works with wrapped error
	if !errors.Is(wrapped, baseErr) {
		t.Error("expected errors.Is to find base error in wrapped error")
	}
}

func TestStageError_ErrorsAs(t *testing.T) {
	baseErr := errors.New("base error")
	wrapped := WrapStageError("stage", baseErr)

	var stageErr *StageError
	if !errors.As(wrapped, &stageErr) {
		t.Fatal("expected errors.As to extract StageError")
	}

	if stageErr.Stage != "stage" {
		t.Errorf("expected stage 'stage', got %q", stageErr.Stage)
	}
}
