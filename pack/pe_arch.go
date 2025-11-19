package pack

import (
	"encoding/binary"
	"fmt"
)

const (
	peMachineI386  = 0x014c
	peMachineAMD64 = 0x8664

	imageSubsystemWindowsGUI = 0x2
	//imageSubsystemWindowsCui   = 0x3
	imageSubsystemWindowsCeGUI = 0x9
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

// detectPESubsystem reads the optional header to discover which Windows subsystem the PE targets.
// The caller can use the returned constant to decide whether the stub should be GUI or CUI.
func detectPESubsystem(data []byte) (uint16, error) {
	if len(data) < 0x40 {
		return 0, fmt.Errorf("file too small to contain DOS header")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return 0, fmt.Errorf("input is not a PE executable")
	}
	peOffset := binary.LittleEndian.Uint32(data[0x3C:])
	if peOffset+0x5C > uint32(len(data)) {
		return 0, fmt.Errorf("invalid PE header offset")
	}
	if string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return 0, fmt.Errorf("missing PE signature")
	}

	optHeaderOffset := peOffset + 24
	if optHeaderOffset+2 > uint32(len(data)) {
		return 0, fmt.Errorf("missing optional header")
	}
	magic := binary.LittleEndian.Uint16(data[optHeaderOffset:])

	var subsystemOffset uint32
	switch magic {
	case 0x10b: // IMAGE_NT_OPTIONAL_HDR32_MAGIC
		subsystemOffset = 68
	case 0x20b: // IMAGE_NT_OPTIONAL_HDR64_MAGIC
		subsystemOffset = 88
	default:
		return 0, fmt.Errorf("unsupported optional header magic 0x%X", magic)
	}

	fieldOffset := optHeaderOffset + subsystemOffset
	if fieldOffset+2 > uint32(len(data)) {
		return 0, fmt.Errorf("optional header truncated")
	}
	return binary.LittleEndian.Uint16(data[fieldOffset : fieldOffset+2]), nil
}
