// go_native.go
// Pure Go executable with MessageBox via syscall
package main

import (
	"syscall"
	"unsafe"
)

func main() {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBox := user32.NewProc("MessageBoxW")

	title, _ := syscall.UTF16PtrFromString("Payload Test - Go Native")
	text, _ := syscall.UTF16PtrFromString(
		"Hello from Go/Native\n\n" +
			"Language: Go\n" +
			"Compiler: Go native (gc)\n" +
			"CGO: Disabled\n" +
			"Runtime: Full Go runtime (~1.5MB)\n" +
			"Features: Goroutines, GC",
	)

	messageBox.Call(
		0,                              // hWnd
		uintptr(unsafe.Pointer(text)),  // lpText
		uintptr(unsafe.Pointer(title)), // lpCaption
		0x00000040,                     // MB_ICONINFORMATION
	)
}
