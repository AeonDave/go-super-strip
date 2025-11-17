# OPERATIONS TESTING & LOGGING

This document explains how we validate every CLI feature (analyze, strip, compact, obfuscate, regex removal, section insertion, overlay, pack) across both PE and ELF binaries. It replaces the Italian write-up that previously shipped with the repo.

## 1. Test Layers

| Layer | Purpose | Entry Point |
|-------|---------|-------------|
| Unit tests | Validate individual helpers (section classifiers, header writers, regex scrubbers). | `go test ./perw ./elfrw ./pack ./common` |
| Integration tests | Exercise the CLI on compiled fixtures, ensuring operations run in canonical order and binaries remain valid. | `go test ./test` |
| Regression scripts | Produce human-readable logs for manual inspection and keep a corpus of before/after analyzer output. | `test/cli_matrix.sh`, `test_polymorphism.sh` |

Always run `go test ./...` before opening a PR. Use the scripts when you need to inspect real binaries or compare analyzer output between commits.

## 2. CLI Integration Coverage

`test/cli_cross_compile_test.go` orchestrates the following scenarios on both PE and ELF fixtures compiled from `testfiles/simple.c` and `testfiles/simple_go.go`:

- `-a`: analyzer simple mode (ensures PE/ELF detection and table output are stable).
- `-s`, `-c`, `-o`: individual operation coverage, verifying “Completed operations: …” appears and no corruption occurs.
- `-i`, `-l`: sector insertion & overlay payload tests ensure data appears on disk.
- `-r`: regex stage removes injected markers.
- `-p`: packer pipeline builds a stub and checks for the expected prefix.

Fixtures compile on the fly. The ELF path uses WSL’s `gcc` when running on Windows; tests skip automatically if cross-compilers are missing.

## 3. CLI Matrix Script

`test/cli_matrix.sh` is a helper that builds `gosstrip`, compiles fresh PE/ELF fixtures, and runs two canonical flows in default and force mode:

1. `analyze → obfuscate → analyze`
2. `analyze → strip → compact → obfuscate → analyze`

All command transcripts (stdout/stderr plus timestamps) land in `tests/logs/cli_matrix_<timestamp>/`. Use these logs to diff analyzer output or to archive regression evidence (e.g., unexpected warnings after changing compact).

Usage:

```bash
bash test/cli_matrix.sh
```

Ensure `x86_64-w64-mingw32-gcc`, `gcc`, and (on Windows) `wsl.exe` are available.

## 4. Polymorphism Script

`test_polymorphism.sh` focuses on the packer’s polymorphic stub. It:

- Builds N packed binaries, checks hash uniqueness, and optionally executes them with a timeout.
- Compares polymorphic vs. non-polymorphic hash counts.
- Reports performance data (build time, average pack time, size deltas).

Run it when touching `pack/` or `testfiles/simple_c`. Quick mode (10 builds) is sufficient for CI; full mode (50 builds) is available for thorough audits.

```bash
./test_polymorphism.sh quick
./test_polymorphism.sh full
```

## 5. Manual Fixture Validation

When investigating analyzer/strip/compact regressions, use the CLI matrix logs plus handcrafted experiments:

```bash
go build -o gosstrip .
./gosstrip -a testfiles/simple_go.exe > logs/pe_simple.txt
./gosstrip -s=force=true -c=fill=random testfiles/simple_go.exe
./gosstrip -a testfiles/simple_go.exe >> logs/pe_simple.txt
```

On Linux/WSL, repeat with `testfiles/simple.c` compiled for ELF. Compare analyzer snapshots to validate timestamp preservation, Go metadata removal, etc.

## 6. Adding New Coverage

When adding a new feature or option:

1. Extend the CLI integration test suite with a new scenario.
2. Update `test/cli_matrix.sh` if the feature affects the canonical flows.
3. Document how to inspect the behavior manually (add a snippet to the relevant technique doc).
4. Reference new tests/scripts here so doc readers know how to run them.

Keeping documentation and scripts in sync with the code makes troubleshooting much faster and ensures we never regress PE or ELF behavior silently.
