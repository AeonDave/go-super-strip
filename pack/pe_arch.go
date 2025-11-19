package pack

import (
	"encoding/binary"
	"fmt"
)

const (
	peMachineI386  = 0x014c
	peMachineAMD64 = 0x8664
)

// detectPEArchitecture inspects the PE headers to determine whether the payload is 32-bit or 64-bit.
// It returns the Go architecture string ("386" or "amd64").
func detectPEArchitecture(data []byte) (string, error) {
	if len(data) < 0x40 {
		return "", fmt.Errorf("file too small to contain DOS header")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return "", fmt.Errorf("input is not a PE executable")
	}
	peOffset := binary.LittleEndian.Uint32(data[0x3C:])
	if peOffset+6 > uint32(len(data)) {
		return "", fmt.Errorf("invalid PE header offset")
	}
	if string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return "", fmt.Errorf("missing PE signature")
	}
	machine := binary.LittleEndian.Uint16(data[peOffset+4 : peOffset+6])
	switch machine {
	case peMachineAMD64:
		return "amd64", nil
	case peMachineI386:
		return "386", nil
	default:
		return "", fmt.Errorf("unsupported PE machine 0x%X", machine)
	}
}
