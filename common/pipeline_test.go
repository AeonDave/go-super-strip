package common

import (
	"errors"
	"strings"
	"testing"
)

func TestNewPipeline(t *testing.T) {
	p := NewPipeline()
	if p == nil {
		t.Fatal("expected NewPipeline to return non-nil pipeline")
	}
	if p.steps == nil {
		t.Error("expected steps slice to be initialized")
	}
	if len(p.steps) != 0 {
		t.Errorf("expected empty pipeline, got %d steps", len(p.steps))
	}
}

func TestAddStep(t *testing.T) {
	p := NewPipeline()

	step1 := func() (*OperationResult, error) {
		return NewApplied("step1", 1), nil
	}
	step2 := func() (*OperationResult, error) {
		return NewApplied("step2", 2), nil
	}

	p.AddStep("first", step1)
	if len(p.steps) != 1 {
		t.Errorf("expected 1 step, got %d", len(p.steps))
	}

	p.AddStep("second", step2)
	if len(p.steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(p.steps))
	}

	if p.steps[0].name != "first" {
		t.Errorf("expected first step name 'first', got %q", p.steps[0].name)
	}
	if p.steps[1].name != "second" {
		t.Errorf("expected second step name 'second', got %q", p.steps[1].name)
	}
}

func TestExecute_EmptyPipeline(t *testing.T) {
	p := NewPipeline()
	aggregate := &OperationResult{
		Applied: false,
		Message: "test",
		Details: []OperationDetail{},
	}

	err := p.Execute(aggregate)
	if err != nil {
		t.Errorf("expected no error for empty pipeline, got %v", err)
	}
	if aggregate.Applied {
		t.Error("expected aggregate.Applied to remain false for empty pipeline")
	}
}

func TestExecute_SingleSuccessfulStep(t *testing.T) {
	p := NewPipeline()
	p.AddStep("strip", func() (*OperationResult, error) {
		return NewApplied("removed 3 sections", 3), nil
	})

	aggregate := NewApplied("pipeline", 0)
	err := p.Execute(aggregate)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !aggregate.Applied {
		t.Error("expected aggregate.Applied to be true")
	}
	if aggregate.Count != 3 {
		t.Errorf("expected aggregate count 3, got %d", aggregate.Count)
	}
	if len(aggregate.Details) != 1 {
		t.Errorf("expected 1 detail, got %d", len(aggregate.Details))
	}
}

func TestExecute_MultipleSuccessfulSteps(t *testing.T) {
	p := NewPipeline()
	p.AddStep("strip", func() (*OperationResult, error) {
		return NewApplied("removed sections", 3), nil
	})
	p.AddStep("compact", func() (*OperationResult, error) {
		return NewApplied("compacted file", 2), nil
	})
	p.AddStep("obfuscate", func() (*OperationResult, error) {
		return NewApplied("obfuscated names", 5), nil
	})

	aggregate := NewApplied("pipeline", 0)
	err := p.Execute(aggregate)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !aggregate.Applied {
		t.Error("expected aggregate.Applied to be true")
	}
	if aggregate.Count != 10 {
		t.Errorf("expected aggregate count 10 (3+2+5), got %d", aggregate.Count)
	}
	if len(aggregate.Details) != 3 {
		t.Errorf("expected 3 details, got %d", len(aggregate.Details))
	}
}

func TestExecute_StepWithError(t *testing.T) {
	p := NewPipeline()
	p.AddStep("step1", func() (*OperationResult, error) {
		return NewApplied("success", 1), nil
	})
	p.AddStep("failing_step", func() (*OperationResult, error) {
		return nil, errors.New("operation failed")
	})
	p.AddStep("step3", func() (*OperationResult, error) {
		return NewApplied("should not execute", 1), nil
	})

	aggregate := NewApplied("pipeline", 0)
	err := p.Execute(aggregate)

	if err == nil {
		t.Fatal("expected error from failing step")
	}
	if !strings.Contains(err.Error(), "failing_step") {
		t.Errorf("expected error to contain step name, got %v", err)
	}
	if !strings.Contains(err.Error(), "operation failed") {
		t.Errorf("expected error to contain original error message, got %v", err)
	}
	// First step should have been applied
	if aggregate.Count != 1 {
		t.Errorf("expected count 1 from first step, got %d", aggregate.Count)
	}
}

func TestExecute_SkippedStep(t *testing.T) {
	p := NewPipeline()
	p.AddStep("skipped", func() (*OperationResult, error) {
		return NewSkipped("not applicable"), nil
	})

	aggregate := &OperationResult{
		Applied: false,
		Message: "pipeline",
		Details: []OperationDetail{},
	}
	err := p.Execute(aggregate)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aggregate.Applied {
		t.Error("expected aggregate.Applied to remain false when all steps skipped")
	}
	if len(aggregate.Details) != 1 {
		t.Errorf("expected 1 detail for skipped step, got %d", len(aggregate.Details))
	}
}

func TestExecute_MixedAppliedAndSkipped(t *testing.T) {
	p := NewPipeline()
	p.AddStep("strip", func() (*OperationResult, error) {
		return NewApplied("removed sections", 3), nil
	})
	p.AddStep("compact", func() (*OperationResult, error) {
		return NewSkipped("no compaction needed"), nil
	})
	p.AddStep("obfuscate", func() (*OperationResult, error) {
		return NewApplied("obfuscated", 2), nil
	})

	aggregate := NewApplied("pipeline", 0)
	err := p.Execute(aggregate)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !aggregate.Applied {
		t.Error("expected aggregate.Applied to be true")
	}
	if aggregate.Count != 5 {
		t.Errorf("expected aggregate count 5 (3+2), got %d", aggregate.Count)
	}
	if len(aggregate.Details) != 3 {
		t.Errorf("expected 3 details (2 applied + 1 skipped), got %d", len(aggregate.Details))
	}
}

func TestExecute_NilAggregate(t *testing.T) {
	p := NewPipeline()
	p.AddStep("step", func() (*OperationResult, error) {
		return NewApplied("test", 1), nil
	})

	// Should not panic with nil aggregate
	err := p.Execute(nil)
	if err != nil {
		t.Errorf("unexpected error with nil aggregate: %v", err)
	}
}

func TestExecute_StepReturnsNilResult(t *testing.T) {
	p := NewPipeline()
	p.AddStep("nil_result", func() (*OperationResult, error) {
		return nil, nil
	})

	aggregate := &OperationResult{
		Applied: false,
		Message: "pipeline",
		Details: []OperationDetail{},
	}
	err := p.Execute(aggregate)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Should handle nil result gracefully
	if aggregate.Applied {
		t.Error("expected aggregate.Applied to remain false")
	}
}

func TestExecute_StepWithDetails(t *testing.T) {
	p := NewPipeline()
	p.AddStep("strip", func() (*OperationResult, error) {
		result := NewApplied("stripped", 3)
		result.AddDetail("removed .debug_info", 1, false)
		result.AddDetail("removed .symtab", 1, true)
		result.AddDetail("removed .strtab", 1, false)
		return result, nil
	})

	aggregate := NewApplied("pipeline", 0)
	err := p.Execute(aggregate)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have 1 detail for the step message + 3 details from the result
	if len(aggregate.Details) != 4 {
		t.Errorf("expected 4 details (1 step + 3 from result), got %d", len(aggregate.Details))
	}
	// Check that risky flag is preserved
	riskyCount := 0
	for _, detail := range aggregate.Details {
		if detail.IsRisky {
			riskyCount++
		}
	}
	if riskyCount != 1 {
		t.Errorf("expected 1 risky detail, got %d", riskyCount)
	}
}

func TestExecute_EmptyStepMessage(t *testing.T) {
	p := NewPipeline()
	p.AddStep("empty_msg", func() (*OperationResult, error) {
		return NewApplied("", 1), nil
	})

	aggregate := NewApplied("pipeline", 0)
	err := p.Execute(aggregate)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aggregate.Count != 1 {
		t.Errorf("expected count 1, got %d", aggregate.Count)
	}
	// Should not add detail when message is empty
	if len(aggregate.Details) != 0 {
		t.Errorf("expected no details for empty message, got %d", len(aggregate.Details))
	}
}
