package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePipeline_AllFeaturesWithOptions(t *testing.T) {
	args := []string{
		"-s=force=true,fill=random",
		"-c=force=true,keep_resources=false",
		"-o=force=true,preserve_load_order=true",
		"-r=pattern=alpha",
		"-r=pattern=beta,fill=zero,force=true",
		"-i=name=.sec,data=payload,password=pass1",
		"-l=data=ov,password=pass2",
		"-ei=name=.sec,password=pass1,destination=sec.bin",
		"-el=password=pass2,destination=ov.bin",
		"input.bin",
		"output.bin",
	}

	cmd, err := parsePipeline(args)
	if err != nil {
		t.Fatalf("parsePipeline returned error: %v", err)
	}
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}

	if cmd.Strip == nil || !cmd.Strip.Force || cmd.Strip.FillModeOverride == nil || !*cmd.Strip.FillModeOverride {
		t.Fatalf("strip options not parsed as expected: %#v", cmd.Strip)
	}
	if cmd.Compact == nil || !cmd.Compact.Force || cmd.Compact.KeepResources {
		t.Fatalf("compact options not parsed as expected: %#v", cmd.Compact)
	}
	if cmd.Obfuscate == nil || !cmd.Obfuscate.Force || !cmd.Obfuscate.PreserveLoadOrder {
		t.Fatalf("obfuscate options not parsed as expected: %#v", cmd.Obfuscate)
	}
	if cmd.Regex == nil || len(cmd.Regex.Patterns) != 2 {
		t.Fatalf("expected two regex patterns, got: %#v", cmd.Regex)
	}
	if cmd.Insert == nil || cmd.Insert.Name != ".sec" || cmd.Insert.Password != "pass1" {
		t.Fatalf("insert options not parsed as expected: %#v", cmd.Insert)
	}
	if cmd.Overlay == nil || cmd.Overlay.Data != "ov" || cmd.Overlay.Password != "pass2" {
		t.Fatalf("overlay options not parsed as expected: %#v", cmd.Overlay)
	}
	if cmd.Extract == nil || cmd.Extract.Destination != "sec.bin" {
		t.Fatalf("extract options not parsed as expected: %#v", cmd.Extract)
	}
	if cmd.ExtractOverlay == nil || cmd.ExtractOverlay.Destination != "ov.bin" {
		t.Fatalf("extract overlay options not parsed as expected: %#v", cmd.ExtractOverlay)
	}
	if cmd.InputPath != "input.bin" || cmd.OutputPath != "output.bin" {
		t.Fatalf("unexpected io paths: input=%q output=%q", cmd.InputPath, cmd.OutputPath)
	}
}

func TestParsePipeline_RejectsOutOfOrderFeatures(t *testing.T) {
	_, err := parsePipeline([]string{"-o", "-s", "input.bin"})
	if err == nil {
		t.Fatal("expected canonical order validation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "canonical order") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePipeline_RejectsDuplicateNonRegexFeatures(t *testing.T) {
	_, err := parsePipeline([]string{"-s", "-s", "input.bin"})
	if err == nil {
		t.Fatal("expected duplicate feature error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "multiple") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePipeline_AcceptsRegexFileAndRepeatedFlags(t *testing.T) {
	dir := t.TempDir()
	patternFile := filepath.Join(dir, "patterns.txt")
	if err := os.WriteFile(patternFile, []byte("# comment\nfoo\nbar\n"), 0o600); err != nil {
		t.Fatalf("failed to write patterns file: %v", err)
	}

	cmd, err := parsePipeline([]string{
		"-r=pattern=" + patternFile,
		"-r=pattern=baz",
		"input.bin",
	})
	if err != nil {
		t.Fatalf("parsePipeline returned error: %v", err)
	}
	if cmd.Regex == nil {
		t.Fatal("expected regex options")
	}
	want := []string{"foo", "bar", "baz"}
	if len(cmd.Regex.Patterns) != len(want) {
		t.Fatalf("unexpected regex pattern count: got=%d want=%d (%v)", len(cmd.Regex.Patterns), len(want), cmd.Regex.Patterns)
	}
	for i, w := range want {
		if cmd.Regex.Patterns[i] != w {
			t.Fatalf("unexpected pattern at %d: got=%q want=%q", i, cmd.Regex.Patterns[i], w)
		}
	}
}

func TestParsePipeline_RejectsUnknownFlag(t *testing.T) {
	_, err := parsePipeline([]string{"-z", "input.bin"})
	if err == nil {
		t.Fatal("expected unknown feature flag error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unknown feature flag") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseAnalyze_Validation(t *testing.T) {
	_, err := parseAnalyze([]string{"-a=format=xml", "input.bin"})
	if err == nil {
		t.Fatal("expected invalid analyze format error")
	}

	_, err = parseAnalyze([]string{"-a=mode=full", "input.bin"})
	if err == nil {
		t.Fatal("expected invalid analyze mode error")
	}
}

func TestParseExtractSection_Validation(t *testing.T) {
	_, err := parseExtractSection("name=.sec,index=1")
	if err == nil {
		t.Fatal("expected name/index exclusivity error")
	}

	_, err = parseExtractSection("")
	if err == nil {
		t.Fatal("expected missing options error")
	}
}

func TestParseRegex_RequiresPattern(t *testing.T) {
	_, err := parseRegex(nil, "fill=random")
	if err == nil {
		t.Fatal("expected missing pattern validation error")
	}
}
