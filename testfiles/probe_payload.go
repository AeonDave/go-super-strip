package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("GOSSTRIP_PROBE_OK")
	if len(os.Args) > 1 {
		fmt.Printf("ARGS:%s\n", os.Args[1:])
	}
}
