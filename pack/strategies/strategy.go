package strategies

import (
	"fmt"
	"sort"
	"strings"
)

// Strategy defines the interface all execution strategies must implement.
// A strategy provides the Go source code compiled into the stub binary that
// is invoked when the packed binary runs its payload.
type Strategy interface {
	// Name returns the unique strategy identifier (e.g. "base_exec", "self_injection").
	Name() string
	// Platform returns the required target platform: "windows", "linux", or "any".
	Platform() string
	// SupportsArch reports whether this strategy supports the given GOARCH value.
	SupportsArch(arch string) bool
	// RuntimeSource returns the Go source file to inject alongside the stub base.
	// arch is the target GOARCH (e.g. "amd64" or "386").
	// The returned source declares an executeStrategy(payload []byte) function
	// plus any additional helpers or variables required by the strategy.
	RuntimeSource(arch string) (string, error)
	// Description returns a human-readable description for logging.
	Description() string
}

var registry = map[string]Strategy{}

// Register adds a strategy to the global registry.
// It panics if a strategy with the same name is already registered.
func Register(s Strategy) {
	if _, exists := registry[s.Name()]; exists {
		panic(fmt.Sprintf("strategies: duplicate registration for %q", s.Name()))
	}
	registry[s.Name()] = s
}

// Get returns the strategy registered under name, or nil if not found.
func Get(name string) Strategy {
	return registry[name]
}

// List returns all registered strategy names in sorted order.
func List() []string {
	names := make([]string, 0, len(registry))
	for k := range registry {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Resolve returns the appropriate strategy for the given name and target platform.
// Special values "", "off", and "base_exec" always resolve to the base_exec strategy.
// "auto" resolves to the platform-specific default: process_hollowing on windows, memfd on linux.
func Resolve(name, platform string) (Strategy, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "", "off", "base_exec":
		s := registry["base_exec"]
		if s == nil {
			return nil, fmt.Errorf("strategies: base_exec not registered")
		}
		return s, nil
	case "auto":
		switch platform {
		case "linux":
			if s := registry["memfd"]; s != nil {
				return s, nil
			}
		default:
			if s := registry["process_hollowing"]; s != nil {
				return s, nil
			}
		}
		// Fall back to base_exec if the platform default is unavailable.
		if s := registry["base_exec"]; s != nil {
			return s, nil
		}
		return nil, fmt.Errorf("strategies: base_exec not registered")
	}

	s := registry[name]
	if s == nil {
		return nil, fmt.Errorf("unknown strategy %q; available: %s",
			name, strings.Join(List(), ", "))
	}
	if p := s.Platform(); p != "any" && p != platform {
		return nil, fmt.Errorf("strategy %q is only available for %s targets (got %s)",
			name, p, platform)
	}
	return s, nil
}

// StripBuildIgnoreTag removes the leading "//go:build ignore\n\n" tag that marks
// runtime source files so they are excluded from the host module's compilation.
// The returned string is a valid Go source file ready to be written to disk.
func StripBuildIgnoreTag(src string) string {
	const tag = "//go:build ignore\n\n"
	if strings.HasPrefix(src, tag) {
		return src[len(tag):]
	}
	return src
}
