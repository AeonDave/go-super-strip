# REGEX REMOVAL STAGE

The `-r` flag removes user-specified byte patterns after obfuscation but before insertion/overlay/pack. This document explains how the grammar works and how the engine applies regexes to PE and ELF binaries.

## 1. CLI Grammar

```
gosstrip ... -r=pattern=marker1,pattern='marker.*2' -r=fill=random,pattern=cleanup_rules.txt <input> [output]
```

- Each `-r` flag must provide at least one `pattern` option. Repeat the option (or the entire `-r` flag) to append more regexes without extra quoting. When the value points to an existing file, every non-empty, non-comment (`# ...`) line becomes a pattern.
- `fill` is optional; omit it for zero overwrites or set `fill=random` to scramble matches before later stages see them.
- Patterns are standard Go regular expressions (`regexp` package), applied in UTF-8 (byte-wise).
- The stage always runs **after** obfuscation so you can remove strings produced by earlier steps.

## 2. Engine Behavior

- Runs over the binaries’ raw bytes, section by section. For PE we scan `.text`, `.rdata`, `.data`, `.rsrc`, overlays; for ELF we scan LOADable segments plus `.rodata`.
- When a pattern matches, we overwrite the bytes with the current fill mode (default zero, optional random when `fill=random` was provided). File-based patterns behave exactly like inline ones; the loader simply expands them ahead of time.
- We never change length or shift offsets. Overlapping matches are handled sequentially (first match wins), then scanning resumes after the replaced region.
- Each match is logged in the operation summary, including section name and offset.

## 3. Default vs. Force

- Force mode for regex simply inherits the global `force` flag when it’s part of a bigger run. It does not alter semantics, but the CLI still reports “force=true” so logs remain accurate.

## 4. Built-in Patterns vs. User Patterns

- Strip already removes known toolchain strings (Go build IDs, GCC banners, PDB paths). Use `-r` for custom indicators (campaign IDs, kill-switch strings, etc.).
- Regex removal is especially useful after insert/overlay if you need to clean up staging markers inserted during earlier steps.

## 5. Testing

- `test/cli_cross_compile_test.go` injects `APPENDED_PATTERN` into each fixture, writes a temporary pattern file (with blank lines and comments), runs `-r=fill=random,pattern=<file>`, and asserts the bytes are gone. This also validates that inline `pattern=PIPELINE_REGEX_TARGET` paths still work within the pipeline scenario.
- Extend that test when adding new regex-specific behavior (e.g., new fill modes).
