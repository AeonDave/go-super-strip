# OPERATIONS TESTING & LOGGING

This document explains how we validate the CLI features (analyze, strip, compact, obfuscate, regex removal, section insertion, overlay, extraction) across both PE and ELF binaries.

## 1. Test Layers

| Layer | Purpose | Entry Point |
|-------|---------|-------------|
| Unit tests | Validate individual helpers (classifiers, writers, regex scrubbers). | `go test ./...` |
| Integration tests | Exercise the CLI on compiled fixtures, ensuring operations run in canonical order and binaries remain valid. | `go test ./test` |
| Regression scripts | Produce human-readable logs for manual inspection and before/after analyzer diffs. | `test/cli_matrix.sh` |

Always run `go test ./...` before opening a PR.

## 2. CLI Integration Coverage

`test/cli_cross_compile_test.go` covers both PE and ELF fixtures compiled from `testfiles/src`:

- `-a`: analyzer output stability.
- `-s`, `-c`, `-o`: individual mutation stages.
- `-i`, `-l`: insertion and overlay payload persistence.
- `-r`: inline and file-based regex rules.
- `-ei`, `-el`: extraction roundtrip checks.
- full pipeline combinations with canonical ordering.

Fixtures compile on the fly. The ELF path uses WSL on Windows when available.

## 3. CLI Matrix Script

`test/cli_matrix.sh` builds `gosstrip`, compiles fresh PE/ELF fixtures, and runs canonical flow families in default and force modes.

Usage:

```bash
bash test/cli_matrix.sh
```

Ensure `x86_64-w64-mingw32-gcc`, `gcc`, and (on Windows) `wsl.exe` are available.

## 4. Manual Fixture Validation

When investigating regressions, use deep analyze snapshots before/after each stage.

Suggested sequence:

1. `-a=mode=deep`
2. `-s` / `-c` / `-o`
3. `-r=pattern=...`
4. `-i` / `-l`
5. `-ei` / `-el`
6. `-a=mode=deep`

Store transcripts under timestamped run folders so comparisons are reproducible.
