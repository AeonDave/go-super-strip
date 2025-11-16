package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

type AnalysisMode string

const (
	AnalysisModeSimple AnalysisMode = "simple"
	AnalysisModeDeep   AnalysisMode = "deep"
)

type AnalysisFormat string

const (
	AnalysisFormatText AnalysisFormat = "text"
	AnalysisFormatJSON AnalysisFormat = "json"
)

type AnalysisOptions struct {
	Mode AnalysisMode
}

func DefaultAnalysisOptions() AnalysisOptions {
	return AnalysisOptions{Mode: AnalysisModeSimple}
}

type AnalysisBlock struct {
	Title string   `json:"title"`
	Lines []string `json:"lines"`
}

type AnalysisResult struct {
	Mode     AnalysisMode    `json:"mode"`
	FileType string          `json:"fileType"`
	Blocks   []AnalysisBlock `json:"blocks,omitempty"`
	Text     string          `json:"text,omitempty"`
	Warnings []string        `json:"warnings,omitempty"`
	Errors   []string        `json:"errors,omitempty"`
}

func (r *AnalysisResult) AddBlock(title string, lines ...string) {
	r.Blocks = append(r.Blocks, AnalysisBlock{
		Title: title,
		Lines: append([]string{}, lines...),
	})
}

func (r *AnalysisResult) AddWarning(msg string) {
	if msg == "" {
		return
	}
	r.Warnings = append(r.Warnings, msg)
}

func (r *AnalysisResult) MergeWarnings(list []string) {
	for _, item := range list {
		r.AddWarning(item)
	}
}

func (r *AnalysisResult) Clone() *AnalysisResult {
	copyRes := *r
	copyRes.Blocks = append([]AnalysisBlock(nil), r.Blocks...)
	copyRes.Warnings = append([]string(nil), r.Warnings...)
	copyRes.Errors = append([]string(nil), r.Errors...)
	return &copyRes
}

func (r *AnalysisResult) MarshalJSONIndented() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func CaptureOutput(fn func() error) (string, error) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	os.Stderr = w

	errCh := make(chan error, 1)
	go func() {
		errCh <- fn()
		_ = w.Close()
	}()

	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, r)
	_ = r.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	fnErr := <-errCh
	if fnErr != nil {
		return buf.String(), fnErr
	}
	if copyErr != nil {
		return buf.String(), copyErr
	}
	return buf.String(), nil
}

func FormatBytes(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024.0)
	}
	if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024.0*1024.0))
	}
	return fmt.Sprintf("%.2f GB", float64(size)/(1024.0*1024.0*1024.0))
}

func SanitizePlainText(in string) string {
	var b strings.Builder
	for _, r := range in {
		if r == '\u0009' || r == '\u000a' || r == '\u000d' {
			b.WriteRune(r)
			continue
		}
		if r < 32 {
			continue
		}
		if unicode.IsPrint(r) && r < 0x2600 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
