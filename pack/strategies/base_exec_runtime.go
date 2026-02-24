//go:build ignore

package main

// base_exec strategy: execute the payload via a temporary file.
// executeFromTemp is declared in the respective platform base runtime file.
func executeStrategy(payload []byte) {
	executeFromTemp(payload)
}
