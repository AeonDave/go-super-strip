package common

import (
	"encoding/binary"
)

// overlayMagic is the 8-byte sentinel appended after every gosstrip overlay payload.
// Format (little-endian): [ payload bytes ] [ magic[8] ] [ length uint32[4] ]
// Total footer size: 12 bytes.
var overlayMagic = [8]byte{'G', 'S', 'S', 'T', 'R', 'I', 'P', 0x00}

const overlayTrailerLen = 12 // 8 magic + 4 length

// WrapOverlayWithTrailer appends the 12-byte trailer to payload and returns the
// combined slice.  The caller is responsible for appending the result to the
// binary's raw data.
func WrapOverlayWithTrailer(payload []byte) []byte {
	out := make([]byte, len(payload)+overlayTrailerLen)
	copy(out, payload)
	copy(out[len(payload):], overlayMagic[:])
	binary.LittleEndian.PutUint32(out[len(payload)+8:], uint32(len(payload)))
	return out
}

// UnwrapOverlayTrailer inspects the last 12 bytes of data for the gosstrip
// trailer.  If found it returns exactly the payload bytes and found=true.
// If the trailer is absent (older format or not a gosstrip overlay), it returns
// data unchanged and found=false, allowing callers to fall back gracefully.
func UnwrapOverlayTrailer(data []byte) (payload []byte, found bool) {
	if len(data) < overlayTrailerLen {
		return data, false
	}
	footerStart := len(data) - overlayTrailerLen
	magic := data[footerStart : footerStart+8]
	for i, b := range overlayMagic {
		if magic[i] != b {
			return data, false
		}
	}
	payloadLen := binary.LittleEndian.Uint32(data[footerStart+8:])
	if int(payloadLen)+overlayTrailerLen > len(data) {
		// Length field is corrupt
		return data, false
	}
	payloadStart := len(data) - overlayTrailerLen - int(payloadLen)
	return data[payloadStart : payloadStart+int(payloadLen)], true
}
