// go_linux.go
// Pure Go executable targeting Linux — no CGO, no Windows APIs.
// Can be cross-compiled from a Windows host:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o out go_linux.go
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stdout,
		"Payload Test - Go Linux\n\n"+
			"Language:  Go\n"+
			"Compiler:  Go native (gc)\n"+
			"CGO:       Disabled\n"+
			"OS/Arch:   %s/%s\n"+
			"Go ver:    %s\n"+
			"Features:  Goroutines, GC, full stdlib\n",
		runtime.GOOS, runtime.GOARCH, runtime.Version(),
	)
}
