package test

import (
	"runtime"
	"testing"

	"gosstrip/common"
	"gosstrip/elfrw"
	"gosstrip/pack"
)

func TestELFPipelineOperations(t *testing.T) {
	if runtime.GOOS != "linux" && !(runtime.GOOS == "windows" && hasWSL()) {
		t.Skip("ELF pipeline verification requires Linux or Windows with WSL")
	}
	t.Setenv("GOSSTRIP_TEST_STUB", testStubPrefix)

	elfPath := buildGoFixture(t, "linux", "simple")

	analyze := func() *common.AnalysisResult {
		return runSimpleAnalysis(t, func() (*common.AnalysisResult, error) {
			return elfrw.AnalyzeELF(elfPath, common.DefaultAnalysisOptions())
		})
	}

	assertAnalysisLooksComprehensive(t, analyze(), "initial analyze")

	requireApplied(t, "strip", elfrw.StripELF(elfPath, false, nil))
	assertAnalysisLooksComprehensive(t, analyze(), "post-strip analyze")

	requireApplied(t, "compact", elfrw.CompactELF(elfPath, false, true))
	assertAnalysisLooksComprehensive(t, analyze(), "post-compact analyze")

	requireApplied(t, "obfuscate", elfrw.ObfuscateELF(elfPath, true))
	assertAnalysisLooksComprehensive(t, analyze(), "post-obfuscate analyze")

	const regexTarget = "ELFPipelineRegexTarget"
	appendPatternToBinary(t, elfPath, regexTarget)
	regexResult := elfrw.RegexELF(elfPath, nil, []string{regexTarget})
	if regexResult == nil || !regexResult.Applied || regexResult.Count == 0 {
		t.Fatalf("expected regex to remove %q, got %#v", regexTarget, regexResult)
	}
	ensureBytesPresence(t, elfPath, regexTarget, "regex removal", false)
	assertAnalysisLooksComprehensive(t, analyze(), "post-regex analyze")

	const sectionPayload = "ELFSectionPipelinePayload"
	requireApplied(t, "insert", elfrw.InsertELF(elfPath, common.SanitizeSectionName(".elfsec"), sectionPayload, ""))
	ensureBytesPresence(t, elfPath, sectionPayload, "section insert", true)
	assertAnalysisLooksComprehensive(t, analyze(), "post-insert analyze")

	const overlayPayload = "ELFOverlayPayloadXYZ"
	requireApplied(t, "overlay", elfrw.OverlayELF(elfPath, overlayPayload, ""))
	ensureBytesPresence(t, elfPath, overlayPayload, "overlay append", true)
	assertAnalysisLooksComprehensive(t, analyze(), "post-overlay analyze")

	runELFBinary(t, elfPath)

	packOpts := "compression=xz,encryption=chacha20,polymorphic=true,padding=true,inmemory=auto"
	if err := pack.Pack(elfPath, packOpts, elfPath); err != nil {
		t.Fatalf("pack.Pack failed: %v", err)
	}

	assertAnalysisLooksComprehensive(t, analyze(), "post-pack analyze")

	runELFBinary(t, elfPath)
}
