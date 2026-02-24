package strategies

import _ "embed"

//go:embed memfd_runtime.go
var memfdSource string

type memfdStrategy struct{}

func (s *memfdStrategy) Name() string               { return "memfd" }
func (s *memfdStrategy) Platform() string           { return "linux" }
func (s *memfdStrategy) SupportsArch(_ string) bool { return true }
func (s *memfdStrategy) RuntimeSource(_ string) (string, error) {
	return StripBuildIgnoreTag(memfdSource), nil
}
func (s *memfdStrategy) Description() string {
	return "write ELF to anonymous memfd and exec in-memory (no disk file)"
}

func init() { Register(&memfdStrategy{}) }
