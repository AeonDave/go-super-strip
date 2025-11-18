package common

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	ErrRegexTimeout      = errors.New("regex evaluation exceeded timeout")
	ErrRegexTooManyMatch = errors.New("regex produced too many matches")
)

var (
	regexTimeout      = 2 * time.Second
	regexMaxMatches   = 100000
	regexFindAllIndex = func(expr *regexp.Regexp, data []byte, limit int) [][]int {
		return expr.FindAllIndex(data, limit)
	}
)

type regexResult struct {
	matches [][]int
	err     error
}

// FindAllRegexMatches evaluates the pattern with an execution timeout and
// a hard cap on returned matches to guard against runaway expressions.
func FindAllRegexMatches(pattern *regexp.Regexp, data []byte) ([][]int, error) {
	if pattern == nil {
		return nil, fmt.Errorf("regex pattern cannot be nil")
	}
	resultCh := make(chan regexResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultCh <- regexResult{err: fmt.Errorf("regex panic: %v", r)}
			}
		}()
		matches := regexFindAllIndex(pattern, data, regexMaxMatches+1)
		resultCh <- regexResult{matches: matches}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			return nil, res.err
		}
		if len(res.matches) > regexMaxMatches {
			return nil, ErrRegexTooManyMatch
		}
		return res.matches, nil
	case <-time.After(regexTimeout):
		return nil, ErrRegexTimeout
	}
}
