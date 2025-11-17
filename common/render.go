package common

import "strings"

func RenderAnalysisText(result *AnalysisResult) string {
	var builder strings.Builder
	header := result.FileType + " ANALYSIS (" + strings.ToUpper(string(result.Mode)) + " mode)"
	builder.WriteString(header)
	builder.WriteByte('\n')
	builder.WriteString(strings.Repeat("=", len(header)))
	builder.WriteString("\n\n")

	if len(result.Blocks) > 0 {
		for _, block := range result.Blocks {
			builder.WriteString(block.Title)
			builder.WriteByte('\n')
			builder.WriteString(strings.Repeat("-", len(block.Title)))
			builder.WriteByte('\n')
			for _, line := range block.Lines {
				builder.WriteString(line)
				if !strings.HasSuffix(line, "\n") {
					builder.WriteByte('\n')
				}
			}
			builder.WriteByte('\n')
		}
	} else if result.Text != "" {
		builder.WriteString(result.Text)
		if !strings.HasSuffix(result.Text, "\n") {
			builder.WriteByte('\n')
		}
	}

	if len(result.Warnings) > 0 {
		builder.WriteString("Warnings:\n")
		for _, w := range result.Warnings {
			builder.WriteString(" - ")
			builder.WriteString(w)
			builder.WriteByte('\n')
		}
		builder.WriteByte('\n')
	}
	if len(result.Errors) > 0 {
		builder.WriteString("Errors:\n")
		for _, w := range result.Errors {
			builder.WriteString(" - ")
			builder.WriteString(w)
			builder.WriteByte('\n')
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}
