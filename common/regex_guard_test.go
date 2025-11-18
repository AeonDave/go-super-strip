package common

import (
	"regexp"
	"testing"
	"time"
)

func TestFindAllRegexMatchesTimeout(t *testing.T) {
	oldFinder := regexFindAllIndex
	oldTimeout := regexTimeout
	regexFindAllIndex = func(_ *regexp.Regexp, _ []byte, _ int) [][]int {
		time.Sleep(20 * time.Millisecond)
		return nil
	}
	regexTimeout = 5 * time.Millisecond
	defer func() {
		regexFindAllIndex = oldFinder
		regexTimeout = oldTimeout
	}()

	_, err := FindAllRegexMatches(regexp.MustCompile("a"), []byte("aaaa"))
	if err == nil || err != ErrRegexTimeout {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestFindAllRegexMatchesLimit(t *testing.T) {
	oldFinder := regexFindAllIndex
	defer func() { regexFindAllIndex = oldFinder }()

	regexFindAllIndex = func(_ *regexp.Regexp, _ []byte, limit int) [][]int {
		matches := make([][]int, limit)
		for i := 0; i < limit; i++ {
			matches[i] = []int{0, 1}
		}
		return matches
	}

	_, err := FindAllRegexMatches(regexp.MustCompile("a"), []byte("aaaa"))
	if err == nil || err != ErrRegexTooManyMatch {
		t.Fatalf("expected too-many-matches error, got %v", err)
	}
}

func TestFindAllRegexMatchesHappyPath(t *testing.T) {
	matches, err := FindAllRegexMatches(regexp.MustCompile("a"), []byte("baacaa"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 4 {
		t.Fatalf("expected 4 matches, got %d", len(matches))
	}
	for _, match := range matches {
		if match[1]-match[0] != 1 {
			t.Fatalf("expected unit match, got %v", match)
		}
	}
}
