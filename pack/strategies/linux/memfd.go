package linux

import (
	"fmt"

	common "gosstrip/pack/strategies/common"
)

// Resolve normalizes the requested mode into a Linux-supported strategy.
func Resolve(mode common.Mode) (common.Mode, error) {
	switch mode {
	case common.ModeOff:
		return common.ModeOff, nil
	case common.ModeAuto, common.ModeMemfd:
		return common.ModeMemfd, nil
	case common.ModeProcessHollowing, common.ModeAtomicBombing:
		return common.ModeOff, fmt.Errorf("in-memory mode %q is only available for PE targets", mode)
	default:
		return common.ModeOff, fmt.Errorf("unknown in-memory mode %q", mode)
	}
}

// Describe produces a human-friendly summary for logs.
func Describe(mode common.Mode) string {
	switch mode {
	case common.ModeOff:
		return "temporary file"
	case common.ModeMemfd:
		return "in-memory (memfd_create)"
	default:
		return fmt.Sprintf("in-memory (%s)", mode)
	}
}

// MemfdRuntime embeds the Go implementation injected into ELF stubs.
const MemfdRuntime = `
// executeInMemory esegue il payload direttamente dalla memoria usando memfd_create
func executeInMemory(payload []byte) {
	// memfd_create syscall (Linux 3.17+)
	// Syscall numbers per architettura:
	// - x86_64: 319
	// - ARM64: 279
	// - ARM: 385
	var memfdSyscall uintptr
	switch runtime.GOARCH {
	case "arm64":
		memfdSyscall = 279
	case "arm":
		memfdSyscall = 385
	default: // x86_64, amd64
		memfdSyscall = 319
	}

	name := []byte("exec\x00")

	// MFD_CLOEXEC = 1
	fd, _, errno := syscall.Syscall(memfdSyscall, uintptr(unsafe.Pointer(&name[0])), 1, 0)
	if errno != 0 {
		// Fallback to temp file if memfd_create not available
		executeFromTemp(payload)
		return
	}
	defer syscall.Close(int(fd))

	// Scrivi payload nel memfd in chunks (gestisce write parziali)
	totalWritten := 0
	for totalWritten < len(payload) {
		n, err := syscall.Write(int(fd), payload[totalWritten:])
		if err != nil {
			executeFromTemp(payload)
			return
		}
		if n <= 0 {
			executeFromTemp(payload)
			return
		}
		totalWritten += n
	}

	// Costruisci path /proc/self/fd/N senza importare fmt
	fdNum := int(fd)
	fdStr := ""
	if fdNum == 0 {
		fdStr = "0"
	} else {
		digits := []byte{}
		for fdNum > 0 {
			digits = append([]byte{byte('0' + fdNum%10)}, digits...)
			fdNum /= 10
		}
		fdStr = string(digits)
	}
	fdPath := "/proc/self/fd/" + fdStr

	// syscall.Exec rimpiazza il processo corrente con il nuovo binary
	args := make([]string, 0, len(elfEmbeddedArgs)+1)
	args = append(args, fdPath)
	if len(elfEmbeddedArgs) > 0 {
		args = append(args, elfEmbeddedArgs...)
	}
	err := syscall.Exec(fdPath, args, os.Environ())

	// Se arriviamo qui, Exec ha fallito - fallback
	if err != nil {
		executeFromTemp(payload)
	}
}
`
