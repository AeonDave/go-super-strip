package strategies

import (
	_ "embed"
	"fmt"
)

//go:embed runtime/self_injection_amd64_runtime.go
var selfInjectionAMD64Source string

//go:embed runtime/self_injection_386_runtime.go
var selfInjection386Source string

type selfInjectionStrategy struct{}

func (s *selfInjectionStrategy) Name() string     { return "self_injection" }
func (s *selfInjectionStrategy) Platform() string { return "windows" }
func (s *selfInjectionStrategy) SupportsArch(arch string) bool {
	return arch == "amd64" || arch == "386"
}
func (s *selfInjectionStrategy) RuntimeSource(arch string) (string, error) {
	switch arch {
	case "386":
		return StripBuildIgnoreTag(selfInjection386Source), nil
	case "amd64", "":
		return StripBuildIgnoreTag(selfInjectionAMD64Source), nil
	default:
		return "", fmt.Errorf("self_injection: unsupported arch %q (supported: amd64, 386)", arch)
	}
}
func (s *selfInjectionStrategy) Description() string {
	return "in-memory self-mapping PE loader with NT stealth thread creation"
}

func init() { Register(&selfInjectionStrategy{}) }
