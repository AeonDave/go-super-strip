package elfrw

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"strings"
)

func decodeSegmentFlags(flags uint32) string {
	var flagStrs []string

	if flags&uint32(common.PERM_READ) != 0 {
		flagStrs = append(flagStrs, "READ")
	}
	if flags&uint32(common.PERM_WRITE) != 0 {
		flagStrs = append(flagStrs, "WRITE")
	}
	if flags&uint32(common.PERM_EXECUTE) != 0 {
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

func formatSizeELF(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	}
}

func formatPresence(present bool) string {
	if present {
		return "✅ Present"
	}
	return "❌ Missing"
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

func (e *ELFFile) readUint32FromBytes(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	if e.isLittleEndian() {
		return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	}
	return uint32(data[3]) | uint32(data[2])<<8 | uint32(data[1])<<16 | uint32(data[0])<<24
}

func (e *ELFFile) readUint64FromBytes(data []byte) uint64 {
	if len(data) < 8 {
		return 0
	}
	if e.isLittleEndian() {
		return uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
			uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
	}
	return uint64(data[7]) | uint64(data[6])<<8 | uint64(data[5])<<16 | uint64(data[4])<<24 |
		uint64(data[3])<<32 | uint64(data[2])<<40 | uint64(data[1])<<48 | uint64(data[0])<<56
}

func (e *ELFFile) readNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
