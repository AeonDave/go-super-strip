package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var stripFlags = []struct {
	name string
	args []string
}{
	{"stripSectionTable", []string{"-s"}},
	{"stripDebug", []string{"-d"}},
	{"stripSymbols", []string{"-y"}},
	{"stripStrings", []string{"-t"}},
	{"stripNonLoadable", []string{"-n"}},
	{"randomizeNames", []string{"-r"}},
	{"stripBuildInfo", []string{"-b"}},
	{"stripProfiling", []string{"-p"}},
	{"stripException", []string{"-e"}},
	{"stripArch", []string{"-a"}},
	{"stripPLTReloc", []string{"-l"}},
	{"stripAll", []string{"-A"}},
}

func TestStrippingFlags(t *testing.T) {
	binDir := "test_bins"
	outDir := "test_out"
	_ = os.MkdirAll(outDir, 0755)
	files, err := filepath.Glob(filepath.Join(binDir, "*"))
	if err != nil {
		t.Fatalf("failed to list test binaries: %v", err)
	}
	for _, f := range files {
		for _, flag := range stripFlags {
			out := filepath.Join(outDir, filepath.Base(f)+"_"+flag.name)
			args := append(flag.args, f)
			cmd := exec.Command("../go-sstrip", args...)
			outf, _ := os.Create(out)
			cmd.Stdout = outf
			cmd.Stderr = outf
			err := cmd.Run()
			_ = outf.Close()
			if err != nil {
				t.Errorf("%s failed on %s: %v", flag.name, f, err)
				continue
			}
			fileCmd := exec.Command("file", out)
			outBytes, _ := fileCmd.CombinedOutput()
			if !isELFValid(string(outBytes)) {
				t.Errorf("Flag %s broke file %s: %s", flag.name, f, string(outBytes))
			}
		}
	}
}

func isELFValid(fileOutput string) bool {
	return len(fileOutput) > 0 && (contains(fileOutput, "ELF") && !contains(fileOutput, "corrupted"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr))))
}
