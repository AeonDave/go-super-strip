# Library Usage

`gosstrip` exposes reusable Go packages so you can manipulate PE/ELF binaries without invoking the CLI.
The example below shows how to analyze a PE file, strip metadata, insert a section, and add/extract an overlay.

```go
package main

import (
	"fmt"

	"gosstrip/common"
	"gosstrip/perw"
)

func main() {
	input := "sample.exe"

	// Analyze in deep mode to capture a full report.
	report, err := perw.AnalyzePE(input, common.AnalysisOptions{Mode: common.AnalysisModeDeep})
	if err != nil {
		panic(err)
	}
	fmt.Println(report.Summary())

	// Strip debug data in force mode and random-fill the wiped regions.
	perw.StripPE(input, true, boolPtr(true))

	// Append a custom section and overlay payload.
	perw.InsertPE(input, ".payload", "SensitiveData", "section-pass")
	perw.OverlayPE(input, "overlay-bytes", "overlay-pass")

	// Read the overlay back for verification.
	rawOverlay, err := perw.ExtractOverlay(input)
	if err != nil {
		panic(err)
	}
	fmt.Printf("overlay size: %d bytes\n", len(rawOverlay))
}

func boolPtr(v bool) *bool { return &v }
```

For ELF binaries, swap the import to `gosstrip/elfrw` and call the analogous helpers
(`AnalyzeELF`, `StripELF`, `InsertELF`, `OverlayELF`, etc.). Always run `gofmt` after editing
and consult `AGENTS.md` for workflow expectations.
