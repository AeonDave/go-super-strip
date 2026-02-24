package strategies

import "fmt"

// aliasStrategy delegates all behaviour to a target strategy but keeps its own
// public name. This lets the CLI accept multiple "inmemory" mode names while
// sharing the same runtime implementation.
type aliasStrategy struct {
	alias  string
	target Strategy
}

func (s *aliasStrategy) Name() string     { return s.alias }
func (s *aliasStrategy) Platform() string { return s.target.Platform() }
func (s *aliasStrategy) SupportsArch(arch string) bool {
	return s.target.SupportsArch(arch)
}
func (s *aliasStrategy) RuntimeSource(arch string) (string, error) {
	return s.target.RuntimeSource(arch)
}
func (s *aliasStrategy) Description() string {
	return fmt.Sprintf("alias for %s", s.target.Name())
}

func registerAlias(alias, targetName string) {
	t := Get(targetName)
	if t == nil {
		// Keep the failure explicit: aliases must be registered after their targets.
		panic(fmt.Sprintf("strategies: alias %q target %q not registered", alias, targetName))
	}
	Register(&aliasStrategy{alias: alias, target: t})
}

func init() {
	// Windows aliases (matrix + docs). These currently share implementations with
	// the hardened process_hollowing/self_injection strategies.
	registerAlias("atomic_bombing", "process_hollowing")
	registerAlias("early_bird", "process_hollowing")
	registerAlias("early_bird_atomic_bombing", "process_hollowing")
	registerAlias("process_doppelganging", "process_hollowing")
	registerAlias("transacted_hollowing", "process_hollowing")
	registerAlias("nt_syscall_reflective", "self_injection")
	registerAlias("reflective_loader", "self_injection")
}
