package main

import "testing"

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
