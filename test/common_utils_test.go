package test

import (
	"encoding/hex"
	"math"
	"testing"

	"gosstrip/common"
)

func almostEqual(a, b, tolerance float64) bool {
	return math.Abs(a-b) <= tolerance
}

func TestCalculateEntropyHandlesUniformAndDiverseData(t *testing.T) {
	zeroEntropy := common.CalculateEntropy([]byte{0, 0, 0, 0})
	if zeroEntropy != 0 {
		t.Fatalf("expected zero entropy, got %f", zeroEntropy)
	}
	mixed := common.CalculateEntropy([]byte{0, 1, 2, 3})
	if !almostEqual(mixed, 2.0, 1e-9) {
		t.Fatalf("expected entropy close to 2, got %f", mixed)
	}
}

func TestCalculateStringEntropy(t *testing.T) {
	if val := common.CalculateStringEntropy("aaaa"); val != 0 {
		t.Fatalf("expected zero entropy, got %f", val)
	}
	if val := common.CalculateStringEntropy("abcd"); !almostEqual(val, 2.0, 1e-9) {
		t.Fatalf("expected entropy close to 2, got %f", val)
	}
}

func TestFormatFileAgeProducesReadableStrings(t *testing.T) {
	if got := common.FormatFileAge(400); got != "1 years, 1 months and 10 days" {
		t.Fatalf("unexpected formatted age: %q", got)
	}
	if got := common.FormatFileAge(15); got != "15 days" { // fallback to days only
		t.Fatalf("unexpected formatted age for short span: %q", got)
	}
}

func TestGenerateRandomBytesReturnsSizedSlice(t *testing.T) {
	data, err := common.GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(data))
	}
}

func TestMatchesPatternSupportsExactAndPrefix(t *testing.T) {
	if !common.MatchesPattern(".text", []string{".text"}, nil) {
		t.Fatal("expected exact match to succeed")
	}
	if !common.MatchesPattern(".data_extra", nil, []string{".data"}) {
		t.Fatal("expected prefix match to succeed")
	}
	if common.MatchesPattern(".rsrc", nil, []string{".data"}) {
		t.Fatal("did not expect match for unrelated prefix")
	}
}

func TestFormatHelpers(t *testing.T) {
	if got := common.FormatFileSize(500); got != "500 B" {
		t.Fatalf("unexpected bytes output: %q", got)
	}
	if got := common.FormatFileSize(2048); got != "2.0 KB" {
		t.Fatalf("unexpected kilobyte output: %q", got)
	}
	if got := common.FormatFileSize(5 * 1024 * 1024); got != "5.00 MB" {
		t.Fatalf("unexpected megabyte output: %q", got)
	}

	if got := common.FormatPermissions(false, true, true); got != "RW-" {
		t.Fatalf("unexpected permissions string: %q", got)
	}
	if got := common.GetEntropyColor(7.6); got != common.ColorRed {
		t.Fatalf("expected high entropy to be red, got %q", got)
	}
	if got := common.GetEntropyColor(6.8); got != common.ColorYellow {
		t.Fatalf("expected medium entropy to be yellow, got %q", got)
	}
	if got := common.GetEntropyColor(5.0); got != common.ColorGreen {
		t.Fatalf("expected low entropy to be green, got %q", got)
	}

	if got := common.TruncateString("abcdefghijkl", 8); got != "abcde..." {
		t.Fatalf("unexpected truncated string: %q", got)
	}

	data := []byte{1, 2, 3}
	common.ZeroFillData(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("expected zero at index %d, got %d", i, b)
		}
	}

	target := make([]byte, 8)
	if err := common.RandomFillData(target); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := common.FirstNonEmpty("", "first", "second"); got != "first" {
		t.Fatalf("unexpected first non empty result: %q", got)
	}
	if got := common.SanitizeSectionName("!!!"); got != ".data" {
		t.Fatalf("expected fallback section name, got %q", got)
	}
	if got := common.SanitizeSectionName("VeryLongName"); got != "VeryLong" {
		t.Fatalf("expected sanitized length, got %q", got)
	}
}

func TestGetEntropyColorBoundaries(t *testing.T) {
	if color := common.GetEntropyColor(7.5); color != common.ColorYellow {
		t.Fatalf("expected boundary to be yellow, got %q", color)
	}
	if color := common.GetEntropyColor(6.5); color != common.ColorGreen {
		t.Fatalf("expected lower boundary to be green, got %q", color)
	}
}

func TestProcessStringForInsertionWithoutPassword(t *testing.T) {
	payload := "HELLO"
	data, err := common.ProcessStringForInsertion(payload, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != payload {
		t.Fatalf("expected unencrypted data, got %q", data)
	}
}

func TestProcessStringForInsertionWithHexPassword(t *testing.T) {
	payload := "HELLO"
	password := "00112233445566778899aabbccddeeff"
	encryptedHex, err := common.ProcessStringForInsertion(payload, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cipher, err := hex.DecodeString(string(encryptedHex))
	if err != nil {
		t.Fatalf("encrypted payload is not valid hex: %v", err)
	}
	passwordBytes, _ := hex.DecodeString(password)
	plain, err := common.DecryptAES256GCM(cipher, passwordBytes)
	if err != nil {
		t.Fatalf("failed to decrypt payload: %v", err)
	}
	if string(plain) != payload {
		t.Fatalf("expected decrypted payload to match, got %q", plain)
	}
}
