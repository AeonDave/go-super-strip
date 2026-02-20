# OPERATIONS TESTING & LOGGING

This document explains how we validate every CLI feature (analyze, strip, compact, obfuscate, regex removal, section insertion, overlay, pack) across both PE and ELF binaries. It replaces the Italian write-up that previously shipped with the repo.

## 1. Test Layers

| Layer | Purpose | Entry Point |
|-------|---------|-------------|
| Unit tests | Validate individual helpers (section classifiers, header writers, regex scrubbers). | `go test ./...` |
| Integration tests | Exercise the CLI on compiled fixtures, ensuring operations run in canonical order and binaries remain valid. | `go test ./test` |
| Regression scripts | Produce human-readable logs for manual inspection and keep a corpus of before/after analyzer output. | `test/cli_matrix.sh`, `test/pack_matrix.ps1` |

Always run `go test ./...` before opening a PR. Use the scripts when you need to inspect real binaries or compare analyzer output between commits.

## 2. CLI Integration Coverage

`test/cli_cross_compile_test.go` orchestrates the following scenarios on both PE and ELF fixtures compiled from `testfiles/simple.c` and `testfiles/simple_go.go`:

- `-a`: analyzer simple mode (ensures PE/ELF detection and table output are stable).
- `-s`, `-c`, `-o`: individual operation coverage, verifying “Completed operations: …” appears and no corruption occurs.
- `-i`, `-l`: section insertion & overlay payload tests ensure data appears on disk.
- `-r`: regex stage removes injected markers via both inline lists (`pattern=PIPELINE_REGEX_TARGET`) and file-based pattern sets (`pattern=/tmp/patterns.txt`), with `fill=random` exercising the override parsing.
- `-ei`: section extraction validates that data inserted during the test run can be recovered by name and index (with and without passwords).
- `-el`: overlay extraction confirms ASCII/hex/file overlays (including encrypted payloads) round-trip correctly.
- `-p`: packer pipeline builds a stub and checks for the expected prefix.

Fixtures compile on the fly. The ELF path uses WSL’s `gcc` when running on Windows; tests skip automatically if cross-compilers are missing.

## 3. CLI Matrix Script

`test/cli_matrix.sh` is a helper that builds `gosstrip`, compiles fresh PE/ELF fixtures, and runs two canonical flow families in default and force mode:

1. `analyze → obfuscate → analyze`
2. `analyze → strip(fill=zero|random) → compact → obfuscate → regex(pattern=file) → analyze`

All command transcripts (stdout/stderr plus timestamps) land in `test/logs/cli_matrix_<timestamp>/`. Use these logs to diff analyzer output or to archive regression evidence (e.g., unexpected warnings after changing compact).

Usage:

```bash
bash test/cli_matrix.sh
```

Ensure `x86_64-w64-mingw32-gcc`, `gcc`, and (on Windows) `wsl.exe` are available.

## 4. Pack Matrix Script

`test/pack_matrix.ps1` (Windows PowerShell) exhaustively validates the packer's polymorphic stubs:

- Builds Windows and Linux `gosstrip` binaries, then compiles fresh C fixtures.
- Drives `analyze(mode=deep) → pack(options) → analyze(mode=deep) → execute` across every compression/encryption/in-memory combination, alternating `polymorphic`, `padding`, `junk_density`, `verbose`, `cleanup`, and `mutation` toggles.
- Checks hash uniqueness across polymorphic builds to confirm each stub is distinct.
- Reports performance data (build time, average pack time, size deltas).
- Logs land under `test/logs/pack_matrix_<timestamp>/` and must be reviewed whenever packer logic changes.

Run it when touching `pack/` or `testfiles/`:

```powershell
pwsh test/pack_matrix.ps1
```

Ensure `x86_64-w64-mingw32-gcc`, `gcc`, and `wsl.exe` are available (ELF execution uses WSL on Windows).

For quick manual investigations without running the full matrix, use `test/manual_pack_flow.ps1` to exercise individual pack option combinations against hand-picked fixtures.

## 5. Manual Fixture Validation

When investigating analyzer/strip/compact regressions, supplement the CLI matrix logs with the manual flows the CLI exposes. For each PE/ELF testfile copy (default + force mode):

1. Append a one-off marker (`ANALYZE_REGEX_MARKER`) and run `-a=mode=deep → -r=pattern=MARKER → -a=mode=deep`.
2. Prepare a newline-delimited pattern file (blank lines/`#` ignored) and run:

   ```
   gosstrip -a=mode=deep <fixture>
   gosstrip -s[=force=true,]fill=zero <fixture>
   gosstrip -c[=force=true] <fixture>
   gosstrip -o[=force=true] <fixture>
   gosstrip -r=pattern=/path/to/patterns.txt <fixture>
   gosstrip -a=mode=deep <fixture>
   ```

3. Repeat step 2 with `fill=random`.
4. When debugging insertion/extraction flows, follow up with `-ei=name=...` or `-ei=index=...` to ensure encrypted payloads can be recovered to disk (specify `destination=` or let it default to `<input>.extracted`). Use `-el=password=...` to pull overlays back out after insertion or pipeline runs.

Store the transcripts under `temp-manual-pipeline/runs/<timestamp>/logs_py/` (or similar) to keep evidence of each run. Comparing the deep analyzer snapshots before/after each stage makes it easier to spot regressions such as missing string wipes or incorrect header rewrites.

## 6. Adding New Coverage

When adding a new feature or option:

1. Extend the CLI integration test suite with a new scenario.
2. Update `test/cli_matrix.sh` if the feature affects the canonical flows.
3. Document how to inspect the behavior manually (add a snippet to the relevant technique doc).
4. Reference new tests/scripts here so doc readers know how to run them.

Keeping documentation and scripts in sync with the code makes troubleshooting much faster and ensures we never regress PE or ELF behavior silently.
