package elfrw

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"
)

func decodeSegmentFlags(flags uint32) string {
	var flagStrs []string

	if flags&uint32(elf.PF_R) != 0 {
		flagStrs = append(flagStrs, "READ")
	}
	if flags&uint32(elf.PF_W) != 0 {
		flagStrs = append(flagStrs, "WRITE")
	}
	if flags&uint32(elf.PF_X) != 0 {
		flagStrs = append(flagStrs, "EXEC")
	}

	if len(flagStrs) == 0 {
		return "None"
	}

	return strings.Join(flagStrs, ", ")
}

func getSegmentTypeName(segmentType uint32) string {
	switch elf.ProgType(segmentType) {
	case elf.PT_NULL:
		return "NULL"
	case elf.PT_LOAD:
		return "LOAD"
	case elf.PT_DYNAMIC:
		return "DYNAMIC"
	case elf.PT_INTERP:
		return "INTERP"
	case elf.PT_NOTE:
		return "NOTE"
	case elf.PT_SHLIB:
		return "SHLIB"
	case elf.PT_PHDR:
		return "PHDR"
	case elf.PT_TLS:
		return "TLS"
	default:
		if segmentType >= uint32(elf.PT_LOPROC) && segmentType <= uint32(elf.PT_HIPROC) {
			return "PROCESSOR_SPECIFIC"
		}
		return fmt.Sprintf("0x%x", segmentType)
	}
}

func (e *ELFFile) IsDynamic() bool {
	return e.ELF != nil && e.ELF.GetFileType() == 3 // ET_DYN
}

func (e *ELFFile) getFileTypeName() string {
	if e.ELF == nil {
		return "Unknown"
	}

	switch e.ELF.GetFileType() {
	case 0:
		return "No file type"
	case 1:
		return "Relocatable"
	case 2:
		return "Executable"
	case 3:
		return "Shared object"
	case 4:
		return "Core file"
	default:
		return fmt.Sprintf("Unknown(0x%x)", e.ELF.GetFileType())
	}
}

func (e *ELFFile) getFileType() uint16 {
	if e.ELF == nil {
		return 0
	}
	return uint16(e.ELF.GetFileType())
}

func (e *ELFFile) isLittleEndian() bool {
	return e.RawData[5] == 0x01 // EI_DATA field, 1 for LSB
}

func (e *ELFFile) getEndian() binary.ByteOrder {
	if e.isLittleEndian() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

func (e *ELFFile) getFileAlignment() int64 {
	if e.Is64Bit {
		return 8
	}
	return 4
}

func (e *ELFFile) readUint64(pos int) uint64 {
	if e.RawData[5] == 1 {
		return binary.LittleEndian.Uint64(e.RawData[pos : pos+8])
	}
	return binary.BigEndian.Uint64(e.RawData[pos : pos+8])
}

func (e *ELFFile) readUint32(pos int) uint32 {
	if e.RawData[5] == 1 {
		return binary.LittleEndian.Uint32(e.RawData[pos : pos+4])
	}
	return binary.BigEndian.Uint32(e.RawData[pos : pos+4])
}

func (e *ELFFile) readUint16(pos int) uint16 {
	if e.RawData[5] == 1 {
		return binary.LittleEndian.Uint16(e.RawData[pos : pos+2])
	}
	return binary.BigEndian.Uint16(e.RawData[pos : pos+2])
}
