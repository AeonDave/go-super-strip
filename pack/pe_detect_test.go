package pack

import (
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// PE test builder
// ---------------------------------------------------------------------------

const (
	testPEOffset = 0x40 // PE header starts at byte 64

	// Machine types
	testMachineAMD64 = 0x8664
	testMachineI386  = 0x014C
	testMachineARM64 = 0xAA64

	// Optional-header magic words
	testMagicPE32  = 0x10B // 32-bit
	testMagicPE32p = 0x20B // 64-bit (PE32+)

	// Subsystem identifiers
	testSubsystemGUI     = 2 // Windows GUI
	testSubsystemConsole = 3 // Windows CUI
)

// buildPE constructs a minimal PE byte slice suitable for testing header
// inspection. Only the fields touched by detectPEArchitecture and
// detectPESubsystem are set; the rest are zeroed.
//
//   - machine:   IMAGE_FILE_MACHINE_* constant
//   - optMagic:  optional-header magic (0x10B or 0x20B)
//   - subsystem: optional-header Subsystem field value
func buildPE(machine, optMagic, subsystem uint16) []byte {
	data := make([]byte, 256)

	// DOS stub
	data[0] = 'M'
	data[1] = 'Z'
	binary.LittleEndian.PutUint32(data[0x3C:], testPEOffset)

	// PE signature
	copy(data[testPEOffset:], []byte{'P', 'E', 0, 0})

	// COFF header: Machine at PE+4
	binary.LittleEndian.PutUint16(data[testPEOffset+4:], machine)

	// Optional header starts at testPEOffset + 24; magic at offset 0.
	optOff := uint32(testPEOffset + 24)
	binary.LittleEndian.PutUint16(data[optOff:], optMagic)

	// Subsystem offset differs by magic (PE32 = 68, PE32+ = 88).
	var subOff uint32
	if optMagic == testMagicPE32 {
		subOff = 68
	} else {
		subOff = 88
	}
	binary.LittleEndian.PutUint16(data[optOff+subOff:], subsystem)

	return data
}

// ---------------------------------------------------------------------------
// detectPEArchitecture
// ---------------------------------------------------------------------------

func TestDetectPEArchitecture(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name: "amd64",
			data: buildPE(testMachineAMD64, testMagicPE32p, testSubsystemConsole),
			want: "amd64",
		},
		{
			name: "i386",
			data: buildPE(testMachineI386, testMagicPE32, testSubsystemConsole),
			want: "386",
		},
		{
			name:    "unsupported_machine",
			data:    buildPE(testMachineARM64, testMagicPE32p, testSubsystemConsole),
			wantErr: true,
		},
		{
			name:    "too_small",
			data:    []byte{0x4D, 0x5A}, // just MZ
			wantErr: true,
		},
		{
			name:    "not_pe_no_mz",
			data:    append([]byte{0x00, 0x00}, make([]byte, 128)...),
			wantErr: true,
		},
		{
			name: "missing_pe_signature",
			data: func() []byte {
				d := buildPE(testMachineAMD64, testMagicPE32p, testSubsystemConsole)
				// Corrupt the PE signature.
				copy(d[testPEOffset:], []byte{'X', 'X', 0, 0})
				return d
			}(),
			wantErr: true,
		},
		{
			name: "pe_offset_out_of_range",
			data: func() []byte {
				d := make([]byte, 128)
				d[0] = 'M'
				d[1] = 'Z'
				// Set PE offset beyond file length.
				binary.LittleEndian.PutUint32(d[0x3C:], 0xFFFF)
				return d
			}(),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := detectPEArchitecture(tc.data)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("detectPEArchitecture() expected error but got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("detectPEArchitecture() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectPESubsystem
// ---------------------------------------------------------------------------

func TestDetectPESubsystem(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		data    []byte
		want    uint16
		wantErr bool
	}{
		{
			name: "pe32_console",
			data: buildPE(testMachineI386, testMagicPE32, testSubsystemConsole),
			want: testSubsystemConsole,
		},
		{
			name: "pe32_gui",
			data: buildPE(testMachineI386, testMagicPE32, testSubsystemGUI),
			want: testSubsystemGUI,
		},
		{
			name: "pe32plus_console",
			data: buildPE(testMachineAMD64, testMagicPE32p, testSubsystemConsole),
			want: testSubsystemConsole,
		},
		{
			name: "pe32plus_gui",
			data: buildPE(testMachineAMD64, testMagicPE32p, testSubsystemGUI),
			want: testSubsystemGUI,
		},
		{
			name:    "too_small",
			data:    []byte{0x4D, 0x5A},
			wantErr: true,
		},
		{
			name:    "not_pe_no_mz",
			data:    append([]byte{0x00, 0x00}, make([]byte, 128)...),
			wantErr: true,
		},
		{
			name: "missing_pe_signature",
			data: func() []byte {
				d := buildPE(testMachineAMD64, testMagicPE32p, testSubsystemGUI)
				copy(d[testPEOffset:], []byte{'X', 'X', 0, 0})
				return d
			}(),
			wantErr: true,
		},
		{
			name: "unknown_opt_magic",
			data: func() []byte {
				d := buildPE(testMachineAMD64, 0x0107 /* ROM image */, testSubsystemGUI)
				return d
			}(),
			wantErr: true,
		},
		{
			name: "pe_offset_out_of_range",
			data: func() []byte {
				d := make([]byte, 128)
				d[0] = 'M'
				d[1] = 'Z'
				binary.LittleEndian.PutUint32(d[0x3C:], 0xFFFF)
				return d
			}(),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := detectPESubsystem(tc.data)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("detectPESubsystem() expected error but got subsystem %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("detectPESubsystem() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}
