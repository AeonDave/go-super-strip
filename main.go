package main

import (
	"errors"
	"fmt"
	"gosstrip/common"
	"gosstrip/elfrw"
	"gosstrip/pack"
	"gosstrip/perw"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const defaultPackOptions = "compression=lzma,level=9,encryption=chacha20"

type feature string

const (
	featureStrip     feature = "strip"
	featureCompact   feature = "compact"
	featureObfuscate feature = "obfuscate"
	featureRegex     feature = "regex"
	featureInsert    feature = "insert"
	featureOverlay   feature = "overlay"
	featurePack      feature = "pack"
)

var canonicalOrder = []feature{
	featureStrip,
	featureCompact,
	featureObfuscate,
	featureRegex,
	featureInsert,
	featureOverlay,
	featurePack,
}

type analyzeCommand struct {
	InputPath  string
	OutputPath string
	Format     string
	Mode       common.AnalysisMode
}

type pipelineCommand struct {
	InputPath  string
	OutputPath string
	Strip      *StripOptions
	Compact    *CompactOptions
	Obfuscate  *ObfuscateOptions
	Regex      *RegexOptions
	Insert     *InsertOptions
	Overlay    *OverlayOptions
	Pack       *PackOptions
}

type StripOptions struct {
	Force bool
}

type CompactOptions struct {
	Force bool
}

type ObfuscateOptions struct {
	Force bool
}

type RegexOptions struct {
	Patterns []string
}

type InsertOptions struct {
	Name     string
	File     string
	Data     string
	Password string
}

type OverlayOptions struct {
	File     string
	Data     string
	Password string
}

type PackOptions struct {
	Options string
}

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	args := os.Args[1:]
	if hasHelp(args) {
		printUsage()
		return
	}

	if isAnalyzeArg(args[0]) {
		cmd, err := parseAnalyze(args)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if err := runAnalyze(cmd); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cmd, err := parsePipeline(args)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if err := runPipeline(cmd); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func hasHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}

func isAnalyzeArg(arg string) bool {
	if !strings.HasPrefix(arg, "-") {
		return false
	}
	trimmed := strings.TrimLeft(arg, "-")
	if trimmed == "a" || trimmed == "analyze" {
		return true
	}
	if strings.HasPrefix(trimmed, "a=") || strings.HasPrefix(trimmed, "analyze=") {
		return true
	}
	return false
}

func parseFeatureFlag(arg string) (string, string, error) {
	if !strings.HasPrefix(arg, "-") {
		return "", "", fmt.Errorf("invalid flag: %s", arg)
	}
	trimmed := strings.TrimLeft(arg, "-")
	if trimmed == "" {
		return "", "", fmt.Errorf("invalid flag: %s", arg)
	}
	parts := strings.SplitN(trimmed, "=", 2)
	name := strings.ToLower(strings.TrimSpace(parts[0]))
	option := ""
	if len(parts) == 2 {
		option = parts[1]
	}
	return name, option, nil
}

func featureByName(name string) (feature, bool) {
	switch strings.ToLower(name) {
	case "s", "strip":
		return featureStrip, true
	case "c", "compact":
		return featureCompact, true
	case "o", "obfuscate":
		return featureObfuscate, true
	case "r", "regex":
		return featureRegex, true
	case "i", "insert":
		return featureInsert, true
	case "l", "overlay":
		return featureOverlay, true
	case "p", "pack":
		return featurePack, true
	default:
		return "", false
	}
}

func featureIndex(f feature) int {
	for i, v := range canonicalOrder {
		if v == f {
			return i
		}
	}
	return -1
}

func parseAnalyze(args []string) (*analyzeCommand, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("missing analyze flag")
	}
	name, opt, err := parseFeatureFlag(args[0])
	if err != nil {
		return nil, err
	}
	if name != "a" && name != "analyze" {
		return nil, fmt.Errorf("unexpected flag %q for analyze", args[0])
	}
	format := "text"
	mode := common.AnalysisModeSimple
	if opt != "" {
		kv, err := parseKeyValueOptions(opt)
		if err != nil {
			return nil, err
		}
		for key, value := range kv {
			switch key {
			case "format":
				switch strings.ToLower(value) {
				case "text", "json":
					format = strings.ToLower(value)
				default:
					return nil, fmt.Errorf("invalid analyze format %q", value)
				}
			case "mode":
				switch strings.ToLower(value) {
				case string(common.AnalysisModeSimple):
					mode = common.AnalysisModeSimple
				case string(common.AnalysisModeDeep):
					mode = common.AnalysisModeDeep
				default:
					return nil, fmt.Errorf("invalid analyze mode %q (expected simple or deep)", value)
				}
			default:
				return nil, fmt.Errorf("unknown analyze option %q", key)
			}
		}
	}
	rest := args[1:]
	if len(rest) == 0 {
		return nil, fmt.Errorf("missing input file")
	}
	if len(rest) > 2 {
		return nil, fmt.Errorf("too many arguments for analyze")
	}
	cmd := &analyzeCommand{InputPath: rest[0], Format: format, Mode: mode}
	if len(rest) == 2 {
		cmd.OutputPath = rest[1]
	}
	return cmd, nil
}

func parsePipeline(args []string) (*pipelineCommand, error) {
	cmd := &pipelineCommand{}
	seen := make(map[feature]bool)
	lastOrder := -1
	idx := 0

	for idx < len(args) && strings.HasPrefix(args[idx], "-") {
		name, opt, err := parseFeatureFlag(args[idx])
		if err != nil {
			return nil, err
		}
		feat, ok := featureByName(name)
		if !ok {
			return nil, fmt.Errorf("unknown feature flag %q", args[idx])
		}
		order := featureIndex(feat)
		if order < 0 {
			return nil, fmt.Errorf("internal error: unknown feature %q", feat)
		}
		if order < lastOrder {
			return nil, fmt.Errorf("feature %s must appear in canonical order", feat)
		}
		if seen[feat] && feat != featureRegex {
			return nil, fmt.Errorf("feature %s specified multiple times", feat)
		}

		switch feat {
		case featureStrip:
			opts, err := parseStrip(opt)
			if err != nil {
				return nil, err
			}
			cmd.Strip = opts
		case featureCompact:
			opts, err := parseCompact(opt)
			if err != nil {
				return nil, err
			}
			cmd.Compact = opts
		case featureObfuscate:
			opts, err := parseObfuscate(opt)
			if err != nil {
				return nil, err
			}
			cmd.Obfuscate = opts
		case featureRegex:
			regexOpts, err := parseRegex(cmd.Regex, opt)
			if err != nil {
				return nil, err
			}
			cmd.Regex = regexOpts
		case featureInsert:
			opts, err := parseInsert(opt)
			if err != nil {
				return nil, err
			}
			cmd.Insert = opts
		case featureOverlay:
			opts, err := parseOverlay(opt)
			if err != nil {
				return nil, err
			}
			cmd.Overlay = opts
		case featurePack:
			opts, err := parsePack(opt)
			if err != nil {
				return nil, err
			}
			cmd.Pack = opts
		}

		if feat != featureRegex {
			seen[feat] = true
		}
		lastOrder = order
		idx++
	}

	if cmd.operationsCount() == 0 {
		return nil, errors.New("no operations specified")
	}

	rest := args[idx:]
	if len(rest) == 0 {
		return nil, fmt.Errorf("missing input file")
	}
	if len(rest) > 2 {
		return nil, fmt.Errorf("too many arguments; expected input [output]")
	}
	cmd.InputPath = rest[0]
	if len(rest) == 2 {
		cmd.OutputPath = rest[1]
	}
	return cmd, nil
}

func parseStrip(opt string) (*StripOptions, error) {
	cfg := &StripOptions{}
	if opt == "" {
		return cfg, nil
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	for key, value := range kv {
		switch key {
		case "force", "f":
			v, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("strip force: %w", err)
			}
			cfg.Force = v
		default:
			return nil, fmt.Errorf("unknown strip option %q", key)
		}
	}
	return cfg, nil
}

func parseCompact(opt string) (*CompactOptions, error) {
	cfg := &CompactOptions{}
	if opt == "" {
		return cfg, nil
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	for key, value := range kv {
		switch key {
		case "force", "f":
			v, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("compact force: %w", err)
			}
			cfg.Force = v
		default:
			return nil, fmt.Errorf("unknown compact option %q", key)
		}
	}
	return cfg, nil
}

func parseObfuscate(opt string) (*ObfuscateOptions, error) {
	cfg := &ObfuscateOptions{}
	if opt == "" {
		return cfg, nil
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	for key, value := range kv {
		switch key {
		case "force", "f":
			v, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("obfuscate force: %w", err)
			}
			cfg.Force = v
		default:
			return nil, fmt.Errorf("unknown obfuscate option %q", key)
		}
	}
	return cfg, nil
}

func parseRegex(existing *RegexOptions, opt string) (*RegexOptions, error) {
	if opt == "" {
		return nil, fmt.Errorf("regex requires at least one pattern")
	}
	patterns := splitList(opt)
	if len(patterns) == 0 {
		return nil, fmt.Errorf("regex requires at least one pattern")
	}
	if existing == nil {
		existing = &RegexOptions{}
	}
	existing.Patterns = append(existing.Patterns, patterns...)
	return existing, nil
}

func parseInsert(opt string) (*InsertOptions, error) {
	if strings.TrimSpace(opt) == "" {
		return nil, fmt.Errorf("insert requires options")
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	name := kv["name"]
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("insert requires name option")
	}
	file := kv["file"]
	data := kv["data"]
	if (file == "" && data == "") || (file != "" && data != "") {
		return nil, fmt.Errorf("insert requires exactly one of file or data")
	}
	return &InsertOptions{
		Name:     name,
		File:     file,
		Data:     data,
		Password: kv["password"],
	}, nil
}

func parseOverlay(opt string) (*OverlayOptions, error) {
	if strings.TrimSpace(opt) == "" {
		return nil, fmt.Errorf("overlay requires options")
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	file := kv["file"]
	data := kv["data"]
	if (file == "" && data == "") || (file != "" && data != "") {
		return nil, fmt.Errorf("overlay requires exactly one of file or data")
	}
	return &OverlayOptions{
		File:     file,
		Data:     data,
		Password: kv["password"],
	}, nil
}

func parsePack(opt string) (*PackOptions, error) {
	optionString := strings.TrimSpace(opt)
	if optionString == "" {
		optionString = defaultPackOptions
	}
	return &PackOptions{Options: optionString}, nil
}

func parseKeyValueOptions(spec string) (map[string]string, error) {
	result := make(map[string]string)
	if strings.TrimSpace(spec) == "" {
		return result, nil
	}
	parts := splitList(spec)
	for _, part := range parts {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid option segment %q", part)
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])
		if key == "" {
			return nil, fmt.Errorf("invalid option segment %q", part)
		}
		result[key] = trimQuotes(value)
	}
	return result, nil
}

func splitList(spec string) []string {
	raw := strings.Split(spec, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		trimmed = trimQuotes(trimmed)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func trimQuotes(value string) string {
	if len(value) >= 2 {
		if (value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", value)
	}
}
func (cmd *pipelineCommand) operationsCount() int {
	count := 0
	if cmd.Strip != nil {
		count++
	}
	if cmd.Compact != nil {
		count++
	}
	if cmd.Obfuscate != nil {
		count++
	}
	if cmd.Regex != nil && len(cmd.Regex.Patterns) > 0 {
		count++
	}
	if cmd.Insert != nil {
		count++
	}
	if cmd.Overlay != nil {
		count++
	}
	if cmd.Pack != nil {
		count++
	}
	return count
}

func runAnalyze(cmd *analyzeCommand) error {
	isPE, err := perw.IsPEFile(cmd.InputPath)
	if err != nil {
		return fmt.Errorf("failed to detect file type: %w", err)
	}
	isELF := false
	if !isPE {
		isELF, err = elfrw.IsELFFile(cmd.InputPath)
		if err != nil {
			return fmt.Errorf("failed to detect file type: %w", err)
		}
	}
	if !isPE && !isELF {
		return fmt.Errorf("unsupported file type: %s", cmd.InputPath)
	}

	opts := common.AnalysisOptions{Mode: cmd.Mode}
	var result *common.AnalysisResult
	if isPE {
		result, err = perw.AnalyzePE(cmd.InputPath, opts)
	} else {
		result, err = elfrw.AnalyzeELF(cmd.InputPath, opts)
	}
	if err != nil {
		return err
	}
	return writeAnalysisResult(result, strings.ToLower(cmd.Format), cmd.OutputPath)
}

func writeAnalysisResult(result *common.AnalysisResult, format, outputPath string) error {
	switch format {
	case "", "text":
		text := renderAnalysisText(result)
		if outputPath != "" {
			return os.WriteFile(outputPath, []byte(text), 0644)
		}
		fmt.Print(text)
		return nil
	case "json":
		data, err := result.MarshalJSONIndented()
		if err != nil {
			return err
		}
		if outputPath != "" {
			return os.WriteFile(outputPath, data, 0644)
		}
		fmt.Println(string(data))
		return nil
	default:
		return fmt.Errorf("unsupported analyze format %q", format)
	}
}

func renderAnalysisText(result *common.AnalysisResult) string {
	var builder strings.Builder
	header := fmt.Sprintf("%s ANALYSIS (%s mode)", result.FileType, strings.ToUpper(string(result.Mode)))
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

func runPipeline(cmd *pipelineCommand) error {
	if err := ensureFileExists(cmd.InputPath); err != nil {
		return err
	}
	workingPath := cmd.InputPath
	if cmd.OutputPath != "" && cmd.OutputPath != cmd.InputPath {
		if err := copyFile(cmd.InputPath, cmd.OutputPath); err != nil {
			return fmt.Errorf("failed to prepare output: %w", err)
		}
		workingPath = cmd.OutputPath
	}

	isPE, isELF, err := detectFileKind(workingPath)
	if err != nil {
		return err
	}
	if !isPE && !isELF {
		return fmt.Errorf("unsupported file type: %s", workingPath)
	}

	var completed []string
	if cmd.Strip != nil {
		if err := runStrip(workingPath, cmd.Strip, isPE); err != nil {
			return err
		}
		completed = append(completed, "strip")
	}
	if cmd.Compact != nil {
		if err := runCompact(workingPath, cmd.Compact, isPE); err != nil {
			return err
		}
		completed = append(completed, "compact")
	}
	if cmd.Obfuscate != nil {
		if err := runObfuscate(workingPath, cmd.Obfuscate, isPE); err != nil {
			return err
		}
		completed = append(completed, "obfuscate")
	}
	if cmd.Regex != nil && len(cmd.Regex.Patterns) > 0 {
		if err := runRegex(workingPath, cmd.Regex.Patterns, isPE); err != nil {
			return err
		}
		completed = append(completed, "regex")
	}
	if cmd.Insert != nil {
		if err := runInsert(workingPath, cmd.Insert, isPE); err != nil {
			return err
		}
		completed = append(completed, "insert")
	}
	if cmd.Overlay != nil {
		if err := runOverlay(workingPath, cmd.Overlay, isPE); err != nil {
			return err
		}
		completed = append(completed, "overlay")
	}
	if cmd.Pack != nil {
		if err := runPack(workingPath, cmd.Pack); err != nil {
			return err
		}
		completed = append(completed, "pack")
	}

	if len(completed) > 0 {
		fmt.Printf("\nCompleted operations: %s\n", strings.Join(completed, ", "))
	}
	return nil
}

func detectFileKind(path string) (bool, bool, error) {
	isPE, err := perw.IsPEFile(path)
	if err != nil {
		return false, false, fmt.Errorf("failed to detect file type: %w", err)
	}
	if isPE {
		return true, false, nil
	}
	isELF, err := elfrw.IsELFFile(path)
	if err != nil {
		return false, false, fmt.Errorf("failed to detect file type: %w", err)
	}
	return false, isELF, nil
}

func runStrip(path string, opts *StripOptions, isPE bool) error {
	fmt.Println("\n=== Strip Operations ===")
	var result *common.OperationResult
	if isPE {
		result = perw.StripPE(path, opts.Force)
	} else {
		result = elfrw.StripELF(path, opts.Force)
	}
	printOperationResult(getFileType(isPE), "strip", result)
	return nil
}

func runCompact(path string, opts *CompactOptions, isPE bool) error {
	fmt.Println("\n=== Compact Operations ===")
	var result *common.OperationResult
	if isPE {
		result = perw.CompactPE(path, opts.Force)
	} else {
		result = elfrw.CompactELF(path, opts.Force)
	}
	printOperationResult(getFileType(isPE), "compact", result)
	return nil
}

func runObfuscate(path string, opts *ObfuscateOptions, isPE bool) error {
	fmt.Println("\n=== Obfuscation Operations ===")
	var result *common.OperationResult
	if isPE {
		result = perw.ObfuscatePE(path, opts.Force)
	} else {
		result = elfrw.ObfuscateELF(path, opts.Force)
	}
	printOperationResult(getFileType(isPE), "obfuscation", result)
	return nil
}

func runRegex(path string, patterns []string, isPE bool) error {
	fmt.Println("\n=== Regex Operations ===")
	for _, pattern := range patterns {
		fmt.Printf("Applying pattern: %s\n", pattern)
		var result *common.OperationResult
		if isPE {
			result = perw.RegexPE(path, pattern)
		} else {
			result = elfrw.RegexELF(path, pattern)
		}
		printOperationResult(getFileType(isPE), "regex", result)
	}
	return nil
}

func runInsert(path string, opts *InsertOptions, isPE bool) error {
	fmt.Printf("\n=== Insert Operations ===\nSection: %s\n", opts.Name)
	payload := opts.Data
	if opts.File != "" {
		payload = opts.File
	}
	var result *common.OperationResult
	if isPE {
		result = perw.InsertPE(path, opts.Name, payload, opts.Password)
	} else {
		result = elfrw.InsertELF(path, opts.Name, payload, opts.Password)
	}
	printOperationResult(getFileType(isPE), "insert", result)
	return nil
}

func runOverlay(path string, opts *OverlayOptions, isPE bool) error {
	fmt.Println("\n=== Overlay Operations ===")
	payload := opts.Data
	if opts.File != "" {
		payload = opts.File
	}
	var result *common.OperationResult
	if isPE {
		result = perw.OverlayPE(path, payload, opts.Password)
	} else {
		result = elfrw.OverlayELF(path, payload, opts.Password)
	}
	printOperationResult(getFileType(isPE), "overlay", result)
	return nil
}

func runPack(path string, opts *PackOptions) error {
	fmt.Println("\n=== Pack Operations ===")
	if err := pack.Pack(path, opts.Options, path); err != nil {
		return fmt.Errorf("pack operation failed: %w", err)
	}
	return nil
}

func printOperationResult(fileType, name string, result *common.OperationResult) {
	if result == nil {
		fmt.Printf("[%s] %s: no result provided\n", fileType, name)
		return
	}
	prefix := "✅"
	if !result.Applied {
		prefix = "⚠️"
	}
	fmt.Printf("%s [%s] %s\n", prefix, fileType, result.Message)
	if len(result.Details) > 0 {
		for _, detail := range result.Details {
			marker := "  •"
			if detail.IsRisky {
				marker = "  ⚠"
			}
			fmt.Printf("%s %s\n", marker, detail.Message)
		}
	}
}

func getFileType(isPE bool) string {
	if isPE {
		return "PE"
	}
	return "ELF"
}

func ensureFileExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("failed to access %s: %w", path, err)
	}
	return nil
}

func copyFile(src, dst string) error {
	if src == dst {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func printUsage() {
	fmt.Println("go-super-strip - Binary transformation pipeline")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  gosstrip -a[=format=json] <input> [output]")
	fmt.Println("  gosstrip [operations] <input> [output]")
	fmt.Println()
	fmt.Println("Operations (executed in order):")
	fmt.Println("  -s=force=true           Strip sections")
	fmt.Println("  -c=force=true           Compact file")
	fmt.Println("  -o=force=true           Obfuscate")
	fmt.Println("  -r=rx1,rx2              Apply regex removals")
	fmt.Println("  -i=name=.sec,file=bin   Insert section")
	fmt.Println("  -l=file=bin             Append overlay")
	fmt.Println("  -p=opt1=val1,...        Pack executable")
	fmt.Println()
	fmt.Println("Specify at least one operation (other than analyze). Use output to write results to a new file; otherwise the input is modified in place.")
}
