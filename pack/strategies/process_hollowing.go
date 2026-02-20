package strategies

import (
	_ "embed"
	"fmt"
)

//go:embed runtime/process_hollowing_amd64_runtime.go
var processHollowingAMD64Source string

//go:embed runtime/process_hollowing_386_runtime.go
var processHollowing386Source string

type processHollowingStrategy struct{}

func (s *processHollowingStrategy) Name() string     { return "process_hollowing" }
func (s *processHollowingStrategy) Platform() string { return "windows" }
func (s *processHollowingStrategy) SupportsArch(arch string) bool {
	return arch == "amd64" || arch == "386"
}
func (s *processHollowingStrategy) RuntimeSource(arch string) (string, error) {
	switch arch {
	case "386":
		return StripBuildIgnoreTag(processHollowing386Source), nil
	case "amd64", "":
		return StripBuildIgnoreTag(processHollowingAMD64Source), nil
	default:
		return "", fmt.Errorf("process_hollowing: unsupported arch %q (supported: amd64, 386)", arch)
	}
}
func (s *processHollowingStrategy) Description() string {
	return "spawn a suspended process, unmap its image, and replace with payload PE"
}

func init() { Register(&processHollowingStrategy{}) }
