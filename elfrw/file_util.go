package elfrw

func (e *ELFFile) logicalFileEnd() int64 {
	fileSize := int64(len(e.RawData))
	clamp := func(value int64) int64 {
		switch {
		case value < 0:
			return 0
		case value > fileSize:
			return fileSize
		default:
			return value
		}
	}

	var maxEnd int64
	for _, section := range e.Sections {
		if section.Type == SHT_NOBITS || section.Offset < 0 || section.Size <= 0 {
			continue
		}
		end := clamp(section.Offset + section.Size)
		if end > maxEnd {
			maxEnd = end
		}
	}
	for _, segment := range e.Segments {
		if segment.FileSize == 0 {
			continue
		}
		end := clamp(int64(segment.Offset + segment.FileSize))
		if end > maxEnd {
			maxEnd = end
		}
	}

	shoffPos, shnumPos, _ := e.getHeaderPositions()
	if shoff, err := e.getSectionHeaderOffset(shoffPos); err == nil {
		entrySize := uint64(0)
		if e.Is64Bit {
			entrySize = uint64(e.readUint16(ELF64_E_SHENTSIZE))
		} else {
			entrySize = uint64(e.readUint16(ELF32_E_SHENTSIZE))
		}
		count := uint64(e.readUint16(shnumPos))
		headerEnd := clamp(int64(shoff + entrySize*count))
		if headerEnd > maxEnd {
			maxEnd = headerEnd
		}
	}

	if shstrEnd := clamp(e.sectionStringTableEnd()); shstrEnd > maxEnd {
		maxEnd = shstrEnd
	}

	return maxEnd
}

func (e *ELFFile) trimZeroTailBeyond(limit int64) {
	if limit <= 0 || limit >= int64(len(e.RawData)) {
		return
	}
	for _, b := range e.RawData[limit:] {
		if b != 0 {
			return
		}
	}
	e.RawData = e.RawData[:limit]
	e.FileSize = int64(len(e.RawData))
	e.HasOverlay = false
	e.OverlayOffset = 0
	e.OverlaySize = 0
}
