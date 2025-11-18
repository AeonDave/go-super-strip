# 🛠️ Agent Guide

This file shares the essential context and ground rules AI coding agents need when working on
`go-super-strip`. Read it before making changes so you can plan and verify work effectively.

---

## Project Snapshot
`go-super-strip` is a Go CLI that inspects and rewrites Windows PE and Linux ELF binaries.
It supports stripping metadata, obfuscating tecnique, compact binaries, inserting/overlaying payloads, applying regex removals,
and packing executables. The tree is organised by file format:

| Directory | Purpose |
|-----------|---------|
| `main.go` | CLI entry point and flag handling |
| `perw/`   | PE (Portable Executable) readers/writers |
| `elfrw/`  | ELF readers/writers plus overlay helpers |
| `pack/`   | Packing/obfuscation logic |
| `test/`   | Cross-platform CLI and integration tests |
| `testfiles/` | Small C/Go programs compiled during tests |

All code is Go, so plan to run `gofmt` on edited files.

---

## Development Workflow

1. **Explore** – use `rg`, `ls`, and `cat`/`Get-Content` to inspect files. Never run destructive Git
   commands (`reset --hard`, `checkout --`).
2. **Edit** – prefer `apply_patch` for single-file updates. Mention binaries or generated files
   explicitly if you cannot modify them.
3. **Format** – run `gofmt -w <files>` on Go files you change.
4. **Test** – run `go test ./...` from the repo root unless the user says otherwise.
   - Integration suites compile binaries and **require**:
     - `wsl.exe` with a functional Linux distro (used to run ELF binaries)
     - `gcc` and, on Windows, `x86_64-w64-mingw32-gcc`
   - Tests skip gracefully if prerequisites are missing, so check logs before assuming failures.
5. **Report** – summarise the change, reference files/lines, and note test status in the final reply.

---

## Special Notes

- **Overlay / ELF tests**: Files in `elfrw/insert_overlay_integration_test.go` build and execute
  binaries inside WSL. If WSL is unavailable, explain why tests were skipped or how you simulated
  the behaviour.
- **Cross-compilation helpers**: `test/cli_cross_compile_test.go` builds C fixtures for both PE and
  ELF flows. When editing, ensure windows/linux code paths keep producing runnable binaries.
- **Sensitive operations**: The tool modifies binary files in-place. When adding new logic,
  verify offsets/lengths carefully and add protective checks (e.g., clamp writes to file size).
- **Helper philosophy**: keep utilities unexported unless they are a stable part of the library API.
  Wrapper logic shared between PE/ELF should flow through `common.ProcessBinary` so open/run/save
  behavior remains consistent, and new error plumbing should prefer `common.StageError` so failures
  include the CLI stage name in both logs and tests.
- **Manual regression logs**:
  - `test/cli_matrix.sh` now compiles PE/ELF fixtures and exercises every CLI flag in canonical order: analyze(deep) → strip(fill=zero/random) → compact → obfuscate → regex → insert → overlay → extract-section → extract-overlay → analyze(deep) for both default and force pipelines. The script also runs single-feature flows (e.g., analyze→regex→analyze) so log directories under `test/logs/cli_matrix_<timestamp>/` always contain baseline + full-pipeline transcripts.
  - For ad-hoc/manual investigations, build the `testfiles/` fixtures, copy them under `temp-manual-pipeline/runs/<timestamp>/work/…`, and log every command (inputs, outputs, gosstrip invocations) under `…/logs/`. Each scenario must start and finish with `analyze(mode=deep)` so before/after states are comparable. Keep payload sources (files, hex snippets, passwords) inside the run directory to allow extraction verification.
    * **Single feature**: `analyze(mode=deep) → <feature flag + options> → analyze(mode=deep)` (PE & ELF, default & force when applicable).
    * **Pipeline (short)**: `analyze(mode=deep) → strip(fill=zero/random,force=false/true) → compact(force=false/true) → obfuscate(force=false/true) → analyze(mode=deep)`.
    * **Pipeline (full)**: `analyze(mode=deep) → strip(fill=zero/random,force=false/true) → compact(force=false/true) → obfuscate(force=false/true) → regex(pattern=…) → insertion(all options) → overlay(all options) → extraction(-ei/-el) → analyze(mode=deep)`.
    * **Pack flow**: `analyze(mode=deep) → pack(all options) → analyze(mode=deep)`.
  - After generating the logs, read them—especially the analyzer summaries at the beginning and end—to surface discrepancies (warnings, runtime errors, or unexpected section/linker states) before reporting back to the user.

---

## Handy Commands

```
# run the full suite
go test ./...

# unit tests for a specific package
go test ./elfrw -run TestName

# format touched Go files
gofmt -w path/to/file.go
```

---

## When In Doubt

- Ask clarifying questions before refactoring large areas.
- Document assumptions in code comments only when behaviour is non-obvious.
- If an external dependency (WSL, compilers) is missing, explain the limitation and provide the
  exact command that failed so the user can reproduce it.

Following this guide will help agents make safe, testable contributions that respect the project’s
structure and tooling.
