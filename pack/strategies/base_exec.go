package strategies

import _ "embed"

//go:embed runtime/base_exec_runtime.go
var baseExecSource string

type baseExecStrategy struct{}

func (s *baseExecStrategy) Name() string               { return "base_exec" }
func (s *baseExecStrategy) Platform() string           { return "any" }
func (s *baseExecStrategy) SupportsArch(_ string) bool { return true }
func (s *baseExecStrategy) RuntimeSource(_ string) (string, error) {
	return StripBuildIgnoreTag(baseExecSource), nil
}
func (s *baseExecStrategy) Description() string {
	return "write to temp file and execute (default, UPX-style)"
}

func init() { Register(&baseExecStrategy{}) }
