package pack

import (
	"bytes"
	"testing"
)

func TestAppendUint64(t *testing.T) {
	tests := []struct {
		name     string
		initial  []byte
		value    uint64
		expected []byte
	}{
		{
			name:     "zero value",
			initial:  []byte{},
			value:    0,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "small value",
			initial:  []byte{},
			value:    0x12,
			expected: []byte{0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "medium value",
			initial:  []byte{},
			value:    0x1234,
			expected: []byte{0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "large value",
			initial:  []byte{},
			value:    0x123456789ABCDEF0,
			expected: []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12},
		},
		{
			name:     "max value",
			initial:  []byte{},
			value:    0xFFFFFFFFFFFFFFFF,
			expected: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name:     "append to existing data",
			initial:  []byte{0xAA, 0xBB},
			value:    0x1234,
			expected: []byte{0xAA, 0xBB, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendUint64(tt.initial, tt.value)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
			// Verify original slice is not modified
			if len(tt.initial) > 0 && &result[0] == &tt.initial[0] {
				t.Error("expected new slice, got reference to original")
			}
		})
	}
}

func TestAppendUint32(t *testing.T) {
	tests := []struct {
		name     string
		initial  []byte
		value    uint32
		expected []byte
	}{
		{
			name:     "zero value",
			initial:  []byte{},
			value:    0,
			expected: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "small value",
			initial:  []byte{},
			value:    0x12,
			expected: []byte{0x12, 0x00, 0x00, 0x00},
		},
		{
			name:     "medium value",
			initial:  []byte{},
			value:    0x1234,
			expected: []byte{0x34, 0x12, 0x00, 0x00},
		},
		{
			name:     "large value",
			initial:  []byte{},
			value:    0x12345678,
			expected: []byte{0x78, 0x56, 0x34, 0x12},
		},
		{
			name:     "max value",
			initial:  []byte{},
			value:    0xFFFFFFFF,
			expected: []byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name:     "append to existing data",
			initial:  []byte{0xAA, 0xBB, 0xCC},
			value:    0x1234,
			expected: []byte{0xAA, 0xBB, 0xCC, 0x34, 0x12, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendUint32(tt.initial, tt.value)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAppendFixedString(t *testing.T) {
	tests := []struct {
		name     string
		initial  []byte
		str      string
		size     int
		expected []byte
	}{
		{
			name:     "empty string with size 0",
			initial:  []byte{},
			str:      "",
			size:     0,
			expected: []byte{},
		},
		{
			name:     "empty string with size 5",
			initial:  []byte{},
			str:      "",
			size:     5,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "short string with padding",
			initial:  []byte{},
			str:      "hi",
			size:     5,
			expected: []byte{'h', 'i', 0x00, 0x00, 0x00},
		},
		{
			name:     "exact size string",
			initial:  []byte{},
			str:      "hello",
			size:     5,
			expected: []byte{'h', 'e', 'l', 'l', 'o'},
		},
		{
			name:     "string longer than size (truncated)",
			initial:  []byte{},
			str:      "hello world",
			size:     5,
			expected: []byte{'h', 'e', 'l', 'l', 'o'},
		},
		{
			name:     "append to existing data",
			initial:  []byte{0xAA, 0xBB},
			str:      "ab",
			size:     4,
			expected: []byte{0xAA, 0xBB, 'a', 'b', 0x00, 0x00},
		},
		{
			name:     "single character",
			initial:  []byte{},
			str:      "x",
			size:     3,
			expected: []byte{'x', 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendFixedString(tt.initial, tt.str, tt.size)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAppendUint64_LittleEndian(t *testing.T) {
	// Verify little-endian byte order explicitly
	result := appendUint64([]byte{}, 0x0102030405060708)
	expected := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(result, expected) {
		t.Errorf("little-endian verification failed: expected %v, got %v", expected, result)
	}
}

func TestAppendUint32_LittleEndian(t *testing.T) {
	// Verify little-endian byte order explicitly
	result := appendUint32([]byte{}, 0x01020304)
	expected := []byte{0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(result, expected) {
		t.Errorf("little-endian verification failed: expected %v, got %v", expected, result)
	}
}

func TestAppendMultipleValues(t *testing.T) {
	// Test chaining multiple append operations
	data := []byte{}
	data = appendUint32(data, 0x12345678)
	data = appendUint64(data, 0xABCDEF0123456789)
	data = appendFixedString(data, "test", 8)

	expectedLen := 4 + 8 + 8
	if len(data) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(data))
	}

	// Verify uint32
	if !bytes.Equal(data[0:4], []byte{0x78, 0x56, 0x34, 0x12}) {
		t.Errorf("uint32 portion incorrect: %v", data[0:4])
	}

	// Verify uint64
	if !bytes.Equal(data[4:12], []byte{0x89, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB}) {
		t.Errorf("uint64 portion incorrect: %v", data[4:12])
	}

	// Verify fixed string
	if !bytes.Equal(data[12:20], []byte{'t', 'e', 's', 't', 0x00, 0x00, 0x00, 0x00}) {
		t.Errorf("fixed string portion incorrect: %v", data[12:20])
	}
}
