package pack

import (
	"fmt"

	stratcommon "gosstrip/pack/strategies/common"
)

// formatInMemoryFallback builds a warning string when the requested in-memory
// mode differs from the resolved mode (excluding auto). Returns empty string
// when no warning is needed.
func formatInMemoryFallback(requested, resolved stratcommon.Mode) string {
	if requested == "" || requested == stratcommon.ModeAuto || requested == resolved {
		return ""
	}

	if resolved == "" || resolved == stratcommon.ModeOff {
		return fmt.Sprintf("⚠ requested in-memory mode %s is unavailable on this target; falling back to temporary file execution", requested)
	}

	return fmt.Sprintf("⚠ requested in-memory mode %s is unavailable on this target; falling back to %s", requested, resolved)
}
