// go_cgo.go
// Go executable with CGO enabled and MessageBox via C
package main

/*
#include <windows.h>

void showMessage() {
    MessageBoxW(
        NULL,
        L"Hello from Go/CGO\n\n"
        L"Language: Go + C\n"
        L"Compiler: Go + CGO (gcc)\n"
        L"CGO: Enabled\n"
        L"Runtime: Go runtime + CGO overhead (~2MB)\n"
        L"Features: C interop, Go runtime",
        L"Payload Test - Go CGO",
        MB_OK | MB_ICONINFORMATION
    );
}
*/
import "C"

func main() {
	C.showMessage()
}
