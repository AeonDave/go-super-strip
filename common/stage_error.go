package common

import "fmt"

// StageError annotates an error with the CLI stage/function that triggered it.
type StageError struct {
	Stage string
	Err   error
}

func (e *StageError) Error() string {
	if e.Stage == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Stage, e.Err)
}

func (e *StageError) Unwrap() error {
	return e.Err
}

// WrapStageError returns a StageError when err is not nil.
func WrapStageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &StageError{Stage: stage, Err: err}
}
