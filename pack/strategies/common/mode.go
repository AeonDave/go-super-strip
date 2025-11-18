package common

import (
	"fmt"
	"strings"
)

// Mode identifies the in-memory execution strategy requested by the CLI.
type Mode string

const (
	ModeOff              Mode = "off"
	ModeAuto             Mode = "auto"
	ModeMemfd            Mode = "memfd"
	ModeProcessHollowing Mode = "process_hollowing"
	ModeAtomicBombing    Mode = "atomic_bombing"
)

// Parse normalizes textual modes coming from CLI flags.
func Parse(value string) (Mode, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return ModeOff, nil
	}
	switch v {
	case string(ModeOff):
		return ModeOff, nil
	case string(ModeAuto):
		return ModeAuto, nil
	case string(ModeMemfd):
		return ModeMemfd, nil
	case string(ModeProcessHollowing):
		return ModeProcessHollowing, nil
	case string(ModeAtomicBombing):
		return ModeAtomicBombing, nil
	default:
		return "", fmt.Errorf("invalid in-memory mode %q (expected off, auto, memfd, process_hollowing, or atomic_bombing)", value)
	}
}

// Enabled reports whether the mode should attempt any in-memory execution strategy.
func (m Mode) Enabled() bool {
	return m != ModeOff && m != ""
}

// Valid reports whether the mode string is recognized.
func (m Mode) Valid() bool {
	switch strings.ToLower(string(m)) {
	case string(ModeOff), string(ModeAuto), string(ModeMemfd), string(ModeProcessHollowing), string(ModeAtomicBombing):
		return true
	default:
		return false
	}
}

func (m Mode) String() string {
	return string(m)
}
