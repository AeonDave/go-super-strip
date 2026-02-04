# REGEX REMOVAL STAGE

The `-r` flag removes user-specified byte patterns. In the pipeline, it runs after obfuscation and before insert/overlay/pack. This document explains how the grammar works and how the engine applies regexes to PE and ELF binaries.

## 1. CLI Grammar

```
gosstrip ... -r=pattern=marker1,pattern='marker.*2' -r=fill=random,pattern=cleanup_rules.txt <input> [output]
```

- Each `-r` flag must provide at least one `pattern` option. Repeat the option (or the entire `-r` flag) to append more regexes. When the value points to an existing file, every non-empty, non-comment (`# ...`) line becomes a pattern.
- `fill` is optional; omit it (or use `fill=zero`) for zero overwrites, or set `fill=random` to scramble matches.
- `force` is optional (`force`, `force=true`, or `force=false`). It disables regex protection ranges when true.
- Patterns are standard Go regular expressions (`regexp` package). They are evaluated against the raw byte stream.

## 2. Engine Behavior

- The engine scans the full raw byte buffer. It does not restrict scanning to individual sections.
- When a pattern matches, we overwrite the bytes with the current fill mode (default zero, optional random when `fill=random` was provided). File-based patterns behave exactly like inline ones; the loader simply expands them ahead of time.
- We never change length or shift offsets. Matches are non-overlapping per Go `FindAllIndex` semantics, and each match is processed in order.
- When replacements occur, trailing zero-only data beyond the last section/segment data may be trimmed.
- Each pattern generates detailed operation messages (match counts and warnings).

## 3. Protections & Force Mode

Regex runs on binaries can easily corrupt execution-critical bytes. When `force=false`, the engine skips matches that overlap protected ranges:

- **PE**: protects a page around the entry point, the import directory/IAT, and (for packed files) high-entropy or large RWX sections that look like packed payloads. UPX header patterns are allowed inside packed payloads, but entry-point and import ranges remain protected.
- **ELF**: protects critical sections, the interpreter path (`PT_INTERP`), `PT_LOAD` segments, and `.shstrtab`.

Set `force=true` to disable these protections for explicit regex requests.

## 4. Built-in Patterns vs. User Patterns

- Strip already removes known toolchain strings (Go build IDs, GCC banners, PDB paths). Use `-r` for custom indicators (campaign IDs, kill-switch strings, etc.).
- Regex removal is especially useful after obfuscation if you need to clean up strings introduced by earlier stages.

## 5. Safety Guards

- Regex evaluation uses a 2-second timeout and caps results at 100,000 matches. Exceeding either results in a pattern error that is recorded and skipped.

## 6. Testing

- `test/cli_cross_compile_test.go` validates pattern files, inline patterns, and pipeline usage.
- `test/perw_operations_test.go` and `test/elf_pipeline_test.go` exercise PE/ELF regex removal, fill overrides, and invalid patterns.
