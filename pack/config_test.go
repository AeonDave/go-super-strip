package pack

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.CompressionAlgorithm != "zlib" {
		t.Errorf("Expected default compression 'zlib', got '%s'", config.CompressionAlgorithm)
	}

	if config.CompressionLevel != 6 {
		t.Errorf("Expected default compression level 6, got %d", config.CompressionLevel)
	}

	if config.EncryptionAlgorithm != "aes-256-gcm" {
		t.Errorf("Expected default encryption 'aes-256-gcm', got '%s'", config.EncryptionAlgorithm)
	}

	if !config.PolymorphicStub {
		t.Error("Expected polymorphic stub to be enabled by default")
	}

	if config.Strategy != "" {
		t.Errorf("Expected strategy to default to empty string, got '%s'", config.Strategy)
	}
}

func TestParseOptions_Empty(t *testing.T) {
	config, err := ParseOptions("")
	if err != nil {
		t.Fatalf("ParseOptions(\"\") failed: %v", err)
	}

	// Should return default config
	if config.CompressionAlgorithm != "zlib" {
		t.Errorf("Expected default compression, got '%s'", config.CompressionAlgorithm)
	}
}

func TestParseOptions_Compression(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"comp=zlib", "zlib", false},
		{"comp=none", "none", false},
		{"compression=zlib", "zlib", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			config, err := ParseOptions(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if config.CompressionAlgorithm != tt.expected {
				t.Errorf("Expected compression '%s', got '%s'", tt.expected, config.CompressionAlgorithm)
			}
		})
	}

	// Test invalid compression with validation
	t.Run("invalid_with_validation", func(t *testing.T) {
		config, err := ParseOptions("comp=invalid")
		if err != nil {
			t.Fatalf("ParseOptions should not fail for invalid value: %v", err)
		}
		err = config.Validate()
		if err == nil {
			t.Error("Expected validation error for invalid compression")
		}
	})
}

func TestParseOptions_Encryption(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"encr=xor", "xor", false},
		{"encr=aes", "aes-256-gcm", false},
		{"encryption=chacha20", "chacha20", false},
		{"encr=none", "none", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			config, err := ParseOptions(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if config.EncryptionAlgorithm != tt.expected {
				t.Errorf("Expected encryption '%s', got '%s'", tt.expected, config.EncryptionAlgorithm)
			}
		})
	}

	// Test invalid encryption with validation
	t.Run("invalid_with_validation", func(t *testing.T) {
		config, err := ParseOptions("encr=invalid")
		if err != nil {
			t.Fatalf("ParseOptions should not fail for invalid value: %v", err)
		}
		err = config.Validate()
		if err == nil {
			t.Error("Expected validation error for invalid encryption")
		}
	})
}

func TestParseOptions_Level(t *testing.T) {
	config, err := ParseOptions("level=9")
	if err != nil {
		t.Fatalf("ParseOptions failed: %v", err)
	}
	if config.CompressionLevel != 9 {
		t.Errorf("Expected level 9, got %d", config.CompressionLevel)
	}
}

func TestParseOptions_Bool(t *testing.T) {
	tests := []struct {
		input string
		check func(*PackConfig) bool
		desc  string
	}{
		{"poly=true", func(c *PackConfig) bool { return c.PolymorphicStub }, "polymorphic"},
		{"poly=false", func(c *PackConfig) bool { return !c.PolymorphicStub }, "polymorphic off"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			config, err := ParseOptions(tt.input)
			if err != nil {
				t.Fatalf("ParseOptions failed: %v", err)
			}
			if !tt.check(config) {
				t.Errorf("Check failed for %s", tt.desc)
			}
		})
	}
}

func TestParseOptions_Multiple(t *testing.T) {
	config, err := ParseOptions("comp=zlib,encr=chacha20,level=9,poly=false,strategy=auto")
	if err != nil {
		t.Fatalf("ParseOptions failed: %v", err)
	}

	if config.CompressionAlgorithm != "zlib" {
		t.Errorf("Expected zlib, got %s", config.CompressionAlgorithm)
	}
	if config.EncryptionAlgorithm != "chacha20" {
		t.Errorf("Expected chacha20, got %s", config.EncryptionAlgorithm)
	}
	if config.CompressionLevel != 9 {
		t.Errorf("Expected level 9, got %d", config.CompressionLevel)
	}
	if config.PolymorphicStub {
		t.Error("Expected polymorphic to be false")
	}
	if config.Strategy != "auto" {
		t.Errorf("Expected strategy auto, got %s", config.Strategy)
	}
}

func TestParseOptions_InvalidFormat(t *testing.T) {
	tests := []string{
		"invalid",
		"key=",
		"=value",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := ParseOptions(input)
			if err == nil {
				t.Errorf("Expected error for input '%s', got nil", input)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*PackConfig)
		wantErr bool
	}{
		{
			name:    "valid default",
			modify:  func(c *PackConfig) {},
			wantErr: false,
		},
		{
			name: "invalid compression",
			modify: func(c *PackConfig) {
				c.CompressionAlgorithm = "invalid"
			},
			wantErr: true,
		},
		{
			name: "invalid encryption",
			modify: func(c *PackConfig) {
				c.EncryptionAlgorithm = "invalid"
			},
			wantErr: true,
		},
		{
			name: "invalid level low",
			modify: func(c *PackConfig) {
				c.CompressionLevel = -1
			},
			wantErr: true,
		},
		{
			name: "invalid level high",
			modify: func(c *PackConfig) {
				c.CompressionLevel = 10
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			tt.modify(config)
			err := config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOptions_Strategy(t *testing.T) {
	t.Run("auto strategy", func(t *testing.T) {
		config, err := ParseOptions("strategy=auto")
		if err != nil {
			t.Fatalf("ParseOptions failed: %v", err)
		}
		if config.Strategy != "auto" {
			t.Fatalf("expected strategy auto, got %s", config.Strategy)
		}
	})
	t.Run("explicit memfd", func(t *testing.T) {
		config, err := ParseOptions("strategy=memfd")
		if err != nil {
			t.Fatalf("ParseOptions failed: %v", err)
		}
		if config.Strategy != "memfd" {
			t.Fatalf("expected strategy memfd, got %s", config.Strategy)
		}
	})
	t.Run("explicit process hollowing", func(t *testing.T) {
		config, err := ParseOptions("strategy=process_hollowing")
		if err != nil {
			t.Fatalf("ParseOptions failed: %v", err)
		}
		if config.Strategy != "process_hollowing" {
			t.Fatalf("expected strategy process_hollowing, got %s", config.Strategy)
		}
	})
	t.Run("self injection", func(t *testing.T) {
		config, err := ParseOptions("strategy=self_injection")
		if err != nil {
			t.Fatalf("ParseOptions failed: %v", err)
		}
		if config.Strategy != "self_injection" {
			t.Fatalf("expected strategy self_injection, got %s", config.Strategy)
		}
	})
	t.Run("base_exec (off/default)", func(t *testing.T) {
		config, err := ParseOptions("strategy=off")
		if err != nil {
			t.Fatalf("ParseOptions failed: %v", err)
		}
		if config.Strategy != "off" {
			t.Fatalf("expected strategy off, got %s", config.Strategy)
		}
	})
	t.Run("inmemory alias accepted", func(t *testing.T) {
		config, err := ParseOptions("inmemory=auto")
		if err != nil {
			t.Fatalf("ParseOptions failed: %v", err)
		}
		if config.Strategy != "auto" {
			t.Fatalf("expected strategy auto via inmemory alias, got %s", config.Strategy)
		}
	})

	t.Run("params option", func(t *testing.T) {
		config, err := ParseOptions("params=-sn 127.0.0.1 -oN out.txt")
		if err != nil {
			t.Fatalf("ParseOptions failed: %v", err)
		}
		if config.Params != "-sn 127.0.0.1 -oN out.txt" {
			t.Fatalf("expected params to round-trip, got %s", config.Params)
		}
	})
}
