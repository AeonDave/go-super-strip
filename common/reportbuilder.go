package common

import (
	"fmt"
	"strings"
)

// ReportBuilder aggregates analyzer sections and warnings so both PE/ELF code paths
// can emit consistent deep reports (text or JSON) without duplicating layout logic.
type ReportBuilder struct {
	fileType string
	mode     AnalysisMode
	blocks   []AnalysisBlock
	warnings []string
	errors   []string
}

func NewReportBuilder(fileType string, mode AnalysisMode) *ReportBuilder {
	return &ReportBuilder{
		fileType: fileType,
		mode:     mode,
		blocks:   make([]AnalysisBlock, 0, 8),
		warnings: make([]string, 0, 4),
		errors:   make([]string, 0, 2),
	}
}

func (b *ReportBuilder) AddSection(title string, lines ...string) {
	clean := trimEmptyLines(lines)
	if len(clean) == 0 {
		return
	}
	b.blocks = append(b.blocks, AnalysisBlock{
		Title: title,
		Lines: append([]string(nil), clean...),
	})
}

func (b *ReportBuilder) AddWarning(msg string) {
	if msg == "" {
		return
	}
	b.warnings = append(b.warnings, msg)
}

func (b *ReportBuilder) MergeWarnings(list []string) {
	for _, item := range list {
		b.AddWarning(item)
	}
}

func (b *ReportBuilder) AddError(msg string) {
	if msg == "" {
		return
	}
	b.errors = append(b.errors, msg)
}

// CaptureSection executes fn while capturing stdout/stderr and adds the emitted
// text as a formatted block. The helper strips the leading banner/underline that
// our analyzers print so the builder can manage headers consistently.
func (b *ReportBuilder) CaptureSection(defaultTitle string, fn func() error) {
	text, err := CaptureOutput(fn)
	if err != nil {
		b.AddWarning(fmt.Sprintf("%s capture failed: %v", defaultTitle, err))
		return
	}
	title, lines := normalizeCapturedSection(defaultTitle, text)
	if len(lines) == 0 {
		return
	}
	b.AddSection(title, lines...)
}

func (b *ReportBuilder) Result() *AnalysisResult {
	return &AnalysisResult{
		FileType: b.fileType,
		Mode:     b.mode,
		Blocks:   append([]AnalysisBlock(nil), b.blocks...),
		Warnings: append([]string(nil), b.warnings...),
		Errors:   append([]string(nil), b.errors...),
	}
}

func normalizeCapturedSection(defaultTitle, raw string) (string, []string) {
	if raw == "" {
		return defaultTitle, nil
	}
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	lines = trimLeadingBlanks(lines)
	if len(lines) == 0 {
		return defaultTitle, nil
	}
	title := defaultTitle
	first := strings.TrimSpace(lines[0])
	if first != "" {
		title = first
		lines = lines[1:]
		if len(lines) > 0 && isDividerLine(lines[0]) {
			lines = lines[1:]
		}
	}
	lines = trimEmptyLines(lines)
	return title, lines
}

func trimLeadingBlanks(lines []string) []string {
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	return append([]string(nil), lines[start:]...)
}

func trimEmptyLines(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	end := len(lines)
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	if start >= end {
		return nil
	}
	clean := make([]string, 0, end-start)
	for _, line := range lines[start:end] {
		clean = append(clean, strings.TrimRight(line, " \t"))
	}
	return clean
}

func isDividerLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	valid := "-=─═━_"
	for _, r := range line {
		if !strings.ContainsRune(valid, r) {
			return false
		}
	}
	return true
}
