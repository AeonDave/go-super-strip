package test

import (
	"runtime"
	"testing"

	"gosstrip/common"
	"gosstrip/pack"
	"gosstrip/perw"
)

func TestPEPipelineOperations(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE pipeline verification requires a Windows host")
	}
	t.Setenv("GOSSTRIP_TEST_STUB", testStubPrefix)

	pePath := buildGoFixture(t, "windows", "simple.exe")

	analyze := func() *common.AnalysisResult {
		return runSimpleAnalysis(t, func() (*common.AnalysisResult, error) {
			return perw.AnalyzePE(pePath, common.DefaultAnalysisOptions())
		})
	}

	assertAnalysisLooksComprehensive(t, analyze(), "initial analyze")

	requireApplied(t, "strip", perw.StripPE(pePath, false, nil))
	assertAnalysisLooksComprehensive(t, analyze(), "post-strip analyze")

	requireApplied(t, "compact", perw.CompactPE(pePath, false, true))
	assertAnalysisLooksComprehensive(t, analyze(), "post-compact analyze")

	requireApplied(t, "obfuscate", perw.ObfuscatePE(pePath, true))
	assertAnalysisLooksComprehensive(t, analyze(), "post-obfuscate analyze")

	const regexTarget = "PEPipelineRegexTarget"
	appendPatternToBinary(t, pePath, regexTarget)
	regexResult := perw.RegexPE(pePath, nil, []string{regexTarget})
	if regexResult == nil || !regexResult.Applied || regexResult.Count == 0 {
		t.Fatalf("expected regex to remove %q, got %#v", regexTarget, regexResult)
	}
	ensureBytesPresence(t, pePath, regexTarget, "regex removal", false)
	assertAnalysisLooksComprehensive(t, analyze(), "post-regex analyze")

	const sectionPayload = "PESectionPipelinePayload"
	sectionName := common.SanitizeSectionName(".pesection")
	requireApplied(t, "insert", perw.InsertPE(pePath, sectionName, sectionPayload, ""))
	ensureBytesPresence(t, pePath, sectionPayload, "section insert", true)
	assertAnalysisLooksComprehensive(t, analyze(), "post-insert analyze")

	const overlayPayload = "PEOverlayPayloadXYZ"
	requireApplied(t, "overlay", perw.OverlayPE(pePath, overlayPayload, ""))
	ensureBytesPresence(t, pePath, overlayPayload, "overlay append", true)
	assertAnalysisLooksComprehensive(t, analyze(), "post-overlay analyze")

	runPEBinary(t, pePath)

	packOpts := "compression=xz,encryption=aes-256-gcm,polymorphic=true,padding=true,inmemory=true,antidebug=true,antivm=true"
	if err := pack.Pack(pePath, packOpts, pePath); err != nil {
		t.Fatalf("pack.Pack failed: %v", err)
	}

	assertAnalysisLooksComprehensive(t, analyze(), "post-pack analyze")

	runPEBinary(t, pePath)
}

func requireApplied(t *testing.T, name string, result *common.OperationResult) {
	t.Helper()
	if result == nil || !result.Applied {
		t.Fatalf("expected %s to apply, got %#v", name, result)
	}
}
