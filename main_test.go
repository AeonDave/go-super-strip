package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseInsertSpec_WindowsPathNoPassword(t *testing.T) {
	section, data, password, err := parseInsertSpec(".sec:C:\\Temp\\data.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if section != ".sec" {
		t.Fatalf("expected section '.sec', got %q", section)
	}
	if data != "C:\\Temp\\data.bin" {
		t.Fatalf("expected data path 'C\\Temp\\data.bin', got %q", data)
	}
	if password != "" {
		t.Fatalf("expected empty password, got %q", password)
	}
}

func TestParseInsertSpec_WindowsPathWithPassword(t *testing.T) {
	section, data, password, err := parseInsertSpec(".sec:C:\\Temp\\data.bin:secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if section != ".sec" {
		t.Fatalf("expected section '.sec', got %q", section)
	}
	if data != "C:\\Temp\\data.bin" {
		t.Fatalf("expected data path 'C\\Temp\\data.bin', got %q", data)
	}
	if password != "secret" {
		t.Fatalf("expected password 'secret', got %q", password)
	}
}

func TestParseInsertSpec_InvalidFormat(t *testing.T) {
	if _, _, _, err := parseInsertSpec(".sec"); err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestParseOverlaySpec_WindowsPathNoPassword(t *testing.T) {
	data, password, err := parseOverlaySpec("C:\\Temp\\payload.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != "C:\\Temp\\payload.bin" {
		t.Fatalf("expected data path 'C\\Temp\\payload.bin', got %q", data)
	}
	if password != "" {
		t.Fatalf("expected empty password, got %q", password)
	}
}

func TestParseOverlaySpec_WithPassword(t *testing.T) {
	data, password, err := parseOverlaySpec("payload.bin:abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != "payload.bin" {
		t.Fatalf("expected data 'payload.bin', got %q", data)
	}
	if password != "abc123" {
		t.Fatalf("expected password 'abc123', got %q", password)
	}
}

func TestSplitValueAndPassword_PathWithColonAndPassword(t *testing.T) {
	data, pass, err := splitValueAndPassword("C:\\path\\with:colon\\file.bin:pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != "C:\\path\\with:colon\\file.bin" {
		t.Fatalf("unexpected data: %q", data)
	}
	if pass != "pass" {
		t.Fatalf("unexpected password: %q", pass)
	}
}

func TestSplitValueAndPassword_InvalidEmpty(t *testing.T) {
	if _, _, err := splitValueAndPassword(""); err == nil {
		t.Fatal("expected error for empty value")
	}
	if _, _, err := splitValueAndPassword(":pass"); err == nil {
		t.Fatal("expected error for missing data before password")
	}
	if _, _, err := splitValueAndPassword("data:"); err == nil {
		t.Fatal("expected error for missing password after colon")
	}
}

func withArgs(args []string, fn func()) {
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = args
	fn()
}

func TestPreprocessPackFlags_DefaultsApplied(t *testing.T) {
	withArgs([]string{"prog", "-p", "file"}, func() {
		preprocessPackFlags()
		if !strings.HasPrefix(os.Args[1], "-p=") || !strings.Contains(os.Args[1], defaultPackOptions) {
			t.Fatalf("expected default pack options applied, got %q", os.Args[1])
		}
	})
	withArgs([]string{"prog", "--pack", "file"}, func() {
		preprocessPackFlags()
		if !strings.HasPrefix(os.Args[1], "--pack=") || !strings.Contains(os.Args[1], defaultPackOptions) {
			t.Fatalf("expected default pack options applied for --pack, got %q", os.Args[1])
		}
	})
	withArgs([]string{"prog", "-p=", "file"}, func() {
		preprocessPackFlags()
		if os.Args[1] != "-p="+defaultPackOptions {
			t.Fatalf("expected '-p=' to become default options, got %q", os.Args[1])
		}
	})
}

func TestPreprocessOperationFlags_ForceParsing(t *testing.T) {
	withArgs([]string{"prog", "-s=force=true", "-o=f=true", "-c=force=false", "file"}, func() {
		preStripForce, preObfForce, preCompactForce = false, false, false
		preprocessOperationFlags()
		if !preStripForce {
			t.Fatalf("expected preStripForce=true")
		}
		if !preObfForce {
			t.Fatalf("expected preObfForce=true")
		}
		if preCompactForce {
			t.Fatalf("expected preCompactForce=false")
		}
		joined := strings.Join(os.Args, " ")
		if strings.Contains(joined, "-s=") || strings.Contains(joined, "-o=") || strings.Contains(joined, "-c=") {
			t.Fatalf("expected -s/-o/-c suboptions normalized to boolean flags, got %q", joined)
		}
	})
}

func TestPlannedOperations_OrderWithPackLast(t *testing.T) {
	cfg := &Configuration{
		Strip:     true,
		Compact:   true,
		Obfuscate: true,
		Insert:    ".sec:data",
		Overlay:   "ovl",
		Regex:     "ABC",
		Pack:      "opts",
	}
	ops := plannedOperations(cfg)
	expected := []string{"strip", "compact", "obfuscate", "insert", "overlay", "regex", "pack"}
	if len(ops) != len(expected) {
		t.Fatalf("unexpected ops length: got %d want %d (%v)", len(ops), len(expected), ops)
	}
	for i := range expected {
		if ops[i] != expected[i] {
			t.Fatalf("order mismatch at %d: got %q want %q (full=%v)", i, ops[i], expected[i], ops)
		}
	}
}
