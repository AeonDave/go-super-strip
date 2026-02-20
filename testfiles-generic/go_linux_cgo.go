// go_linux_cgo.go
// Go executable with CGO enabled, using the native Linux C runtime.
// Must be compiled on a Linux host (or inside WSL) where gcc is available:
//
//	CGO_ENABLED=1 go build -ldflags="-s -w" -o out go_linux_cgo.go
package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void show_info(const char *goVersion, const char *goArch) {
    printf(
        "Payload Test - Go Linux CGO\n\n"
        "Language:  Go + C\n"
        "Compiler:  Go + CGO (gcc)\n"
        "CGO:       Enabled\n"
        "OS/Arch:   linux/%s\n"
        "Go ver:    %s\n"
        "Features:  C interop, Go runtime\n",
        goArch, goVersion
    );
    fflush(stdout);
}
*/
import "C"
import "runtime"

func main() {
	C.show_info(C.CString(runtime.Version()), C.CString(runtime.GOARCH))
}
