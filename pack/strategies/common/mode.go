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
	ModeSelfInjection    Mode = "self_injection"
	ModeNtSyscallReflect Mode = "nt_syscall_reflective"
	ModeReflectiveLoader Mode = "reflective_loader"
	ModeEarlyBird        Mode = "early_bird"
	ModeEarlyBirdAtomic  Mode = "early_bird_atomic_bombing"
	ModeProcessDoppel    Mode = "process_doppelganging"
	ModeTransactedHollow Mode = "transacted_hollowing"
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
	case string(ModeProcessDoppel):
		return ModeProcessDoppel, nil
	case string(ModeTransactedHollow):
		return ModeTransactedHollow, nil
	case string(ModeSelfInjection):
		return ModeSelfInjection, nil
	case string(ModeNtSyscallReflect):
		return ModeNtSyscallReflect, nil
	case string(ModeReflectiveLoader):
		return ModeReflectiveLoader, nil
	case string(ModeEarlyBird):
		return ModeEarlyBird, nil
	case string(ModeEarlyBirdAtomic):
		return ModeEarlyBirdAtomic, nil
	default:
		return "", fmt.Errorf("invalid in-memory mode %q (expected off, auto, memfd, process_hollowing, atomic_bombing, early_bird, early_bird_atomic_bombing, process_doppelganging, transacted_hollowing, self_injection, nt_syscall_reflective, or reflective_loader)", value)
	}
}

// Enabled reports whether the mode should attempt any in-memory execution strategy.
func (m Mode) Enabled() bool {
	return m != ModeOff && m != ""
}

// Valid reports whether the mode string is recognized.
func (m Mode) Valid() bool {
	switch strings.ToLower(string(m)) {
	case string(ModeOff), string(ModeAuto), string(ModeMemfd), string(ModeProcessHollowing), string(ModeAtomicBombing), string(ModeProcessDoppel), string(ModeTransactedHollow), string(ModeSelfInjection), string(ModeNtSyscallReflect), string(ModeReflectiveLoader), string(ModeEarlyBird):
		return true
	case string(ModeEarlyBirdAtomic):
		return true
	default:
		return false
	}
}

func (m Mode) String() string {
	return string(m)
}
