package main

import (
	"bufio"
	"errors"
	"fmt"
	"gosstrip/common"
	"gosstrip/elfrw"
	"gosstrip/perw"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type feature string

const (
	featureStrip          feature = "strip"
	featureCompact        feature = "compact"
	featureObfuscate      feature = "obfuscate"
	featureRegex          feature = "regex"
	featureInsert         feature = "insert"
	featureOverlay        feature = "overlay"
	featureExtract        feature = "extract"
	featureOverlayExtract feature = "extractoverlay"
)

var canonicalOrder = []feature{
	featureStrip,
	featureCompact,
	featureObfuscate,
	featureRegex,
	featureInsert,
	featureOverlay,
	featureExtract,
	featureOverlayExtract,
}

type analyzeCommand struct {
	InputPath  string
	OutputPath string
	Format     string
	Mode       common.AnalysisMode
}

type pipelineCommand struct {
	InputPath      string
	OutputPath     string
	Strip          *StripOptions
	Compact        *CompactOptions
	Obfuscate      *ObfuscateOptions
	Regex          *RegexOptions
	Insert         *InsertOptions
	Overlay        *OverlayOptions
	Extract        *ExtractSectionOptions
	ExtractOverlay *ExtractOverlayOptions
}

type StripOptions struct {
	Force            bool
	FillModeOverride *bool
}

type CompactOptions struct {
	Force         bool
	KeepResources bool
}

type ObfuscateOptions struct {
	Force             bool
	PreserveLoadOrder bool
}

type RegexOptions struct {
	Patterns         []string
	FillModeOverride *bool
	Force            bool
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

type ExtractSectionOptions struct {
	Name        string
	Index       *int
	Password    string
	Destination string
}

type ExtractOverlayOptions struct {
	Password    string
	Destination string
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}
	if hasVersion(args) {
		printVersion()
		return
	}
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

func hasVersion(args []string) bool {
	for _, a := range args {
		if a == "-v" || a == "--version" || a == "version" {
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
	case "ei", "extract", "extractinsert":
		return featureExtract, true
	case "el", "extractoverlay":
		return featureOverlayExtract, true
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
		for key, values := range kv {
			value := values[len(values)-1]
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
		case featureOverlayExtract:
			opts, err := parseExtractOverlay(opt)
			if err != nil {
				return nil, err
			}
			cmd.ExtractOverlay = opts
		case featureExtract:
			opts, err := parseExtractSection(opt)
			if err != nil {
				return nil, err
			}
			cmd.Extract = opts
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
	for key, values := range kv {
		value := values[len(values)-1]
		switch key {
		case "force", "f":
			v, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("strip force: %w", err)
			}
			cfg.Force = v
		case "fill":
			v := strings.ToLower(value)
			switch v {
			case "", "auto":
				cfg.FillModeOverride = nil
			case "zero":
				cfg.FillModeOverride = boolPtr(false)
			case "random":
				cfg.FillModeOverride = boolPtr(true)
			default:
				return nil, fmt.Errorf("strip fill: expected auto, zero, or random, got %q", value)
			}
		default:
			return nil, fmt.Errorf("unknown strip option %q", key)
		}
	}
	return cfg, nil
}

func parseCompact(opt string) (*CompactOptions, error) {
	cfg := &CompactOptions{KeepResources: true}
	if opt == "" {
		return cfg, nil
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	for key, values := range kv {
		value := values[len(values)-1]
		switch key {
		case "force", "f":
			v, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("compact force: %w", err)
			}
			cfg.Force = v
		case "keep_resources", "keep-resources", "keepresources":
			v, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("compact keep_resources: %w", err)
			}
			cfg.KeepResources = v
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
	for key, values := range kv {
		value := values[len(values)-1]
		switch key {
		case "force", "f":
			v, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("obfuscate force: %w", err)
			}
			cfg.Force = v
		case "preserve_load_order", "preserve-load-order", "keep_load_order", "keep-load-order":
			v, err := parseBool(value)
			if err != nil {
				return nil, fmt.Errorf("obfuscate preserve_load_order: %w", err)
			}
			cfg.PreserveLoadOrder = v
		default:
			return nil, fmt.Errorf("unknown obfuscate option %q", key)
		}
	}
	return cfg, nil
}

func parseRegex(existing *RegexOptions, opt string) (*RegexOptions, error) {
	if strings.TrimSpace(opt) == "" {
		return nil, fmt.Errorf("regex requires options")
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, fmt.Errorf("regex options: %w", err)
	}
	if len(kv) == 0 {
		return nil, fmt.Errorf("regex requires at least one option")
	}
	if existing == nil {
		existing = &RegexOptions{}
	}
	for key, values := range kv {
		switch key {
		case "force":
			value := values[len(values)-1]
			if value == "" {
				existing.Force = true
				continue
			}
			v, err := strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("regex force: %w", err)
			}
			existing.Force = v
		case "fill":
			value := values[len(values)-1]
			switch strings.ToLower(value) {
			case "", "zero":
				v := false
				existing.FillModeOverride = &v
			case "random":
				v := true
				existing.FillModeOverride = &v
			default:
				return nil, fmt.Errorf("regex fill: expected zero or random, got %q", value)
			}
		case "pattern", "patterns":
			for _, value := range values {
				patterns, err := loadPatternOptions(value)
				if err != nil {
					return nil, err
				}
				existing.Patterns = append(existing.Patterns, patterns...)
			}
		default:
			return nil, fmt.Errorf("unknown regex option %q", key)
		}
	}
	if len(existing.Patterns) == 0 {
		return nil, fmt.Errorf("regex requires at least one pattern")
	}
	return existing, nil
}

func loadPatternOptions(value string) ([]string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("regex pattern list cannot be empty")
	}
	if patterns, ok, err := readPatternFile(trimmed); err != nil {
		return nil, err
	} else if ok {
		return patterns, nil
	}
	patterns := splitList(value)
	if len(patterns) == 0 {
		return nil, fmt.Errorf("regex pattern list cannot be empty")
	}
	return patterns, nil
}

func readPatternFile(path string) ([]string, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("regex pattern file %q: %w", path, err)
	}
	if info.IsDir() {
		return nil, false, fmt.Errorf("regex pattern file %q: expected file, found directory", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("regex pattern file %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	var patterns []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("regex pattern file %q: %w", path, err)
	}
	if len(patterns) == 0 {
		return nil, false, fmt.Errorf("regex pattern file %q contains no usable patterns", path)
	}
	return patterns, true, nil
}

func parseInsert(opt string) (*InsertOptions, error) {
	if strings.TrimSpace(opt) == "" {
		return nil, fmt.Errorf("insert requires options")
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	file := kv.last("file")
	data := kv.last("data")
	if (file == "" && data == "") || (file != "" && data != "") {
		return nil, fmt.Errorf("insert requires exactly one of file or data")
	}
	return &InsertOptions{
		Name:     kv.last("name"),
		File:     file,
		Data:     data,
		Password: kv.last("password"),
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
	file := kv.last("file")
	data := kv.last("data")
	if (file == "" && data == "") || (file != "" && data != "") {
		return nil, fmt.Errorf("overlay requires exactly one of file or data")
	}
	return &OverlayOptions{
		File:     file,
		Data:     data,
		Password: kv.last("password"),
	}, nil
}

func parseExtractOverlay(opt string) (*ExtractOverlayOptions, error) {
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	return &ExtractOverlayOptions{
		Password:    kv.last("password"),
		Destination: kv.last("destination"),
	}, nil
}

func parseExtractSection(opt string) (*ExtractSectionOptions, error) {
	if strings.TrimSpace(opt) == "" {
		return nil, fmt.Errorf("extract requires options")
	}
	kv, err := parseKeyValueOptions(opt)
	if err != nil {
		return nil, err
	}
	name := kv.last("name")
	indexStr := kv.last("index")
	if strings.TrimSpace(name) == "" && strings.TrimSpace(indexStr) == "" {
		return nil, fmt.Errorf("extract requires name or index")
	}
	if strings.TrimSpace(name) != "" && strings.TrimSpace(indexStr) != "" {
		return nil, fmt.Errorf("extract accepts either name or index, not both")
	}
	var idx *int
	if strings.TrimSpace(indexStr) != "" {
		value, err := strconv.Atoi(indexStr)
		if err != nil || value < 0 {
			return nil, fmt.Errorf("extract index must be a non-negative integer")
		}
		idx = &value
	}
	return &ExtractSectionOptions{
		Name:        name,
		Index:       idx,
		Password:    kv.last("password"),
		Destination: kv.last("destination"),
	}, nil
}

type optionMap map[string][]string

func parseKeyValueOptions(spec string) (optionMap, error) {
	result := make(optionMap)
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
		result[key] = append(result[key], trimQuotes(value))
	}
	return result, nil
}

func (m optionMap) last(key string) string {
	if len(m) == 0 {
		return ""
	}
	values := m[key]
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
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
	if cmd.Extract != nil {
		count++
	}
	if cmd.ExtractOverlay != nil {
		count++
	}
	return count
}

func (cmd *pipelineCommand) extractOnly() bool {
	if cmd.operationsCount() != 1 {
		return false
	}
	return cmd.Extract != nil || cmd.ExtractOverlay != nil
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
		text := common.RenderAnalysisText(result)
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

func runPipeline(cmd *pipelineCommand) error {
	if err := ensureFileExists(cmd.InputPath); err != nil {
		return err
	}
	workingPath := cmd.InputPath
	extractDestOverride := ""
	if cmd.extractOnly() {
		if cmd.OutputPath != "" && cmd.OutputPath != cmd.InputPath {
			extractDestOverride = cmd.OutputPath
		}
	} else if cmd.OutputPath != "" && cmd.OutputPath != cmd.InputPath {
		if err := copyFile(cmd.InputPath, cmd.OutputPath); err != nil {
			return fmt.Errorf("failed to prepare output: %w", err)
		}
		workingPath = cmd.OutputPath
	}
	if cmd.Extract != nil && cmd.Extract.Destination == "" && extractDestOverride != "" {
		cmd.Extract.Destination = extractDestOverride
	}
	if cmd.ExtractOverlay != nil && cmd.ExtractOverlay.Destination == "" && extractDestOverride != "" {
		cmd.ExtractOverlay.Destination = extractDestOverride
	}

	isPE, isELF, err := detectFileKind(workingPath)
	if err != nil {
		return err
	}
	if !isPE && !isELF {
		return fmt.Errorf("unsupported file type: %s", workingPath)
	}

	session := newCommandSession(getFileType(isPE))
	if cmd.Strip != nil {
		session.addStep("strip", func() (*common.OperationResult, error) {
			return runStrip(workingPath, cmd.Strip, isPE)
		})
	}
	if cmd.Compact != nil {
		session.addStep("compact", func() (*common.OperationResult, error) {
			return runCompact(workingPath, cmd.Compact, isPE)
		})
	}
	if cmd.Obfuscate != nil {
		session.addStep("obfuscation", func() (*common.OperationResult, error) {
			return runObfuscate(workingPath, cmd.Obfuscate, isPE)
		})
	}
	if cmd.Regex != nil && len(cmd.Regex.Patterns) > 0 {
		session.addStep("regex", func() (*common.OperationResult, error) {
			return runRegex(workingPath, cmd.Regex, isPE)
		})
	}
	if cmd.Insert != nil {
		session.addStep("insert", func() (*common.OperationResult, error) {
			return runInsert(workingPath, cmd.Insert, isPE)
		})
	}
	if cmd.Overlay != nil {
		session.addStep("overlay", func() (*common.OperationResult, error) {
			return runOverlay(workingPath, cmd.Overlay, isPE)
		})
	}
	if cmd.Extract != nil {
		session.addStep("extract-section", func() (*common.OperationResult, error) {
			return runExtractSection(workingPath, cmd.InputPath, cmd.Extract, isPE)
		})
	}
	if cmd.ExtractOverlay != nil {
		session.addStep("extract-overlay", func() (*common.OperationResult, error) {
			return runExtractOverlay(workingPath, cmd.InputPath, cmd.ExtractOverlay, isPE)
		})
	}

	summary, err := session.execute()
	if err != nil {
		return err
	}
	fmt.Println("\n=== Pipeline Summary ===")
	printOperationResult(session.fileType, "pipeline", summary)
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

func runStrip(path string, opts *StripOptions, isPE bool) (*common.OperationResult, error) {
	if opts == nil {
		return common.NewSkipped("no strip options provided"), nil
	}
	if isPE {
		if res := perw.StripPE(path, opts.Force, opts.FillModeOverride); res != nil {
			return res, nil
		}
	} else if res := elfrw.StripELF(path, opts.Force, opts.FillModeOverride); res != nil {
		return res, nil
	}
	return nil, common.WrapStageError("strip", fmt.Errorf("strip operation returned no result"))
}

func runCompact(path string, opts *CompactOptions, isPE bool) (*common.OperationResult, error) {
	if opts == nil {
		return common.NewSkipped("no compact options provided"), nil
	}
	keepResources := opts.KeepResources
	if isPE {
		if res := perw.CompactPE(path, opts.Force, keepResources); res != nil {
			return res, nil
		}
	} else if res := elfrw.CompactELF(path, opts.Force, keepResources); res != nil {
		return res, nil
	}
	return nil, common.WrapStageError("compact", fmt.Errorf("compact operation returned no result"))
}

func runObfuscate(path string, opts *ObfuscateOptions, isPE bool) (*common.OperationResult, error) {
	if opts == nil {
		opts = &ObfuscateOptions{}
	}
	if isPE {
		if res := perw.ObfuscatePE(path, opts.Force); res != nil {
			return res, nil
		}
	} else if res := elfrw.ObfuscateELF(path, opts.Force, opts.PreserveLoadOrder); res != nil {
		return res, nil
	}
	return nil, common.WrapStageError("obfuscate", fmt.Errorf("obfuscation operation returned no result"))
}

func runRegex(path string, opts *RegexOptions, isPE bool) (*common.OperationResult, error) {
	if opts == nil || len(opts.Patterns) == 0 {
		return common.NewSkipped("no regex patterns provided"), nil
	}
	var result *common.OperationResult
	if isPE {
		result = perw.RegexPE(path, opts.FillModeOverride, opts.Patterns, opts.Force)
	} else {
		result = elfrw.RegexELF(path, opts.FillModeOverride, opts.Patterns, opts.Force)
	}
	if result == nil {
		return common.NewSkipped("regex operation returned no result"), nil
	}
	return result, nil
}

func runInsert(path string, opts *InsertOptions, isPE bool) (*common.OperationResult, error) {
	payload := opts.Data
	if opts.File != "" {
		payload = opts.File
	}
	if isPE {
		return perw.InsertPE(path, opts.Name, payload, opts.Password), nil
	}
	return elfrw.InsertELF(path, opts.Name, payload, opts.Password), nil
}

func runOverlay(path string, opts *OverlayOptions, isPE bool) (*common.OperationResult, error) {
	payload := opts.Data
	if opts.File != "" {
		payload = opts.File
	}
	if isPE {
		return perw.OverlayPE(path, payload, opts.Password), nil
	}
	return elfrw.OverlayELF(path, payload, opts.Password), nil
}

func runExtractSection(path, inputPath string, opts *ExtractSectionOptions, isPE bool) (*common.OperationResult, error) {
	if opts == nil {
		return common.NewSkipped("no extract options provided"), nil
	}
	destination := opts.Destination
	if destination == "" {
		destination = inputPath + ".extracted"
	}
	dir := filepath.Dir(destination)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, common.WrapStageError("extract-section", fmt.Errorf("failed to prepare destination directory: %w", err))
		}
	}
	var (
		data        []byte
		sectionName string
		err         error
	)
	if isPE {
		data, sectionName, err = perw.ExtractSection(path, opts.Name, opts.Index, opts.Password)
	} else {
		data, sectionName, err = elfrw.ExtractSection(path, opts.Name, opts.Index, opts.Password)
	}
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to extract section: %v", err)), nil
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		return nil, common.WrapStageError("extract-section", fmt.Errorf("failed to write extracted data: %w", err))
	}
	result := common.NewApplied(fmt.Sprintf("extracted section '%s' to %s", sectionName, destination), len(data))
	result.SetCategory("EXTRACT")
	return result, nil
}

func runExtractOverlay(path, inputPath string, opts *ExtractOverlayOptions, isPE bool) (*common.OperationResult, error) {
	if opts == nil {
		return common.NewSkipped("no overlay extract options provided"), nil
	}
	destination := opts.Destination
	if destination == "" {
		destination = inputPath + ".extracted"
	}
	dir := filepath.Dir(destination)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, common.WrapStageError("extract-overlay", fmt.Errorf("failed to prepare destination directory: %w", err))
		}
	}
	var (
		data []byte
		err  error
	)
	if isPE {
		data, err = perw.ExtractOverlay(path)
	} else {
		data, err = elfrw.ExtractOverlay(path)
	}
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to extract overlay: %v", err)), nil
	}
	decoded, err := common.ProcessExtractedData(data, opts.Password)
	if err != nil {
		return nil, common.WrapStageError("extract-overlay", err)
	}
	if err := os.WriteFile(destination, decoded, 0o600); err != nil {
		return nil, common.WrapStageError("extract-overlay", fmt.Errorf("failed to write extracted overlay: %w", err))
	}
	result := common.NewApplied(fmt.Sprintf("extracted overlay to %s", destination), len(decoded))
	result.SetCategory("OVERLAY_EXTRACT")
	return result, nil
}

func boolPtr(v bool) *bool {
	return &v
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
	fmt.Printf("go-super-strip v%s - Binary transformation pipeline\n", Version)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  gosstrip -v")
	fmt.Println("  gosstrip -a[=format=json,mode=deep] <input> [output]")
	fmt.Println("  gosstrip [operations] <input> [output]")
	fmt.Println()
	fmt.Println("Operations (executed in order):")
	fmt.Println("  -s=force=true           Strip sections")
	fmt.Println("  -c=force=true,keep_resources=false Compact file")
	fmt.Println("  -o=force=true           Obfuscate")
	fmt.Println("  -r=pattern=rx[,pattern=rules.txt][,fill=random][,force=true] Apply regex removals")
	fmt.Println("  -i=name=.sec,file=bin   Insert section")
	fmt.Println("  -l=file=bin             Append overlay")
	fmt.Println("  -ei=name=.sec[,index=0][,password=pass] Extract a section to disk")
	fmt.Println("  -el[=password=pass]     Extract overlay payload")
	fmt.Println()
	fmt.Println("Analyze (-a), extract-section (-ei), and extract-overlay (-el) can be invoked standalone just like any other stage.")
	fmt.Println()
	fmt.Println("Specify at least one operation (other than analyze). Use output to write results to a new file; otherwise the input is modified in place.")
}

func printVersion() {
	fmt.Printf("go-super-strip v%s\n", Version)
}

type commandSession struct {
	fileType  string
	pipeline  *common.Pipeline
	aggregate *common.OperationResult
}

func newCommandSession(fileType string) *commandSession {
	return &commandSession{
		fileType: fileType,
		pipeline: common.NewPipeline(),
		aggregate: &common.OperationResult{
			Message: fmt.Sprintf("%s pipeline", fileType),
			Details: []common.OperationDetail{},
		},
	}
}

func (s *commandSession) addStep(name string, fn func() (*common.OperationResult, error)) {
	s.pipeline.AddStep(name, func() (*common.OperationResult, error) {
		result, err := fn()
		if err != nil {
			return nil, err
		}
		if result != nil {
			printOperationResult(s.fileType, name, result)
		} else {
			fmt.Printf("[%s] %s: no result provided\n", s.fileType, name)
		}
		return result, nil
	})
}

func (s *commandSession) execute() (*common.OperationResult, error) {
	if err := s.pipeline.Execute(s.aggregate); err != nil {
		return nil, err
	}
	if s.aggregate.Applied {
		s.aggregate.Message = fmt.Sprintf("%s pipeline summary", strings.ToUpper(s.fileType))
	} else {
		s.aggregate.Message = "no operations applied"
	}
	return s.aggregate, nil
}
