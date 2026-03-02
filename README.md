# go-super-strip

A cross-platform binary transformation toolkit for Windows PE and Linux ELF executables.

`go-super-strip` inspects and rewrites binaries — stripping metadata, compacting dead space, obfuscating headers, scrubbing patterns with regex, inserting encrypted payloads, managing overlays, and extracting sections. Every operation is designed to produce output that **looks like normal compiler output**, minimising detection surface for AV/EDR heuristics.

## Features

- **Unified CLI** — same flags work on both PE and ELF binaries; format is auto-detected.
- **Deterministic pipeline** — operations execute in a fixed canonical order so results are reproducible.
- **Safe defaults** — default mode applies only low-risk, well-understood transforms; `force=true` unlocks aggressive research-only operations.
- **Stealth-first obfuscation** — section names are NULL-wiped (not renamed), timestamps and padding are zeroed (not randomised), runtime strings are zero-filled. The approach follows the principle: *the best obfuscation looks like normal compilation output*.
- **Deep analysis** — JSON-capable analyser reports entropy, hashes, permissions, overlay presence, packer detection, and more.
- **Encrypted payloads** — AES-encrypted section insertion and overlay appending with password-based key derivation.

## Requirements

- **Go 1.24+**
- **Optional** (for integration tests):
  - `gcc` and `x86_64-w64-mingw32-gcc` for cross-compilation fixtures
  - `wsl.exe` with a functional Linux distro for ELF binary execution tests

## Installation

```bash
git clone https://github.com/AeonDave/go-super-strip
cd go-super-strip
go build -o gosstrip      # Linux / macOS
go build -o gosstrip.exe  # Windows
```

Override the embedded version at build time:

```bash
go build -ldflags "-X main.Version=1.0.0" -o gosstrip
```

## Usage

```
gosstrip -v
gosstrip -a[=format=json,mode=deep] <input> [output]
gosstrip [operations...] <input> [output]
```

- `-v` prints the version and exits.
- `-a` (analyse) runs standalone; optionally writes the report to `output`.
- When multiple operations are given the CLI enforces the canonical order below and mutates `input` in-place unless `output` is supplied.

### Pipeline Order

```
analyse (standalone)
  │
strip    (-s)
  │
compact  (-c)
  │
obfuscate (-o)
  │
regex    (-r)  ← repeatable
  │
insert   (-i)
  │
overlay  (-l)
  │
extract section  (-ei)
  │
extract overlay  (-el)
```

## Flags & Options

| Flag | Purpose | Defaults |
|------|---------|----------|
| `-a[=format=text\|json,mode=simple\|deep]` | Analyse PE/ELF metadata. JSON is available in deep mode only. | `format=text`, `mode=simple` |
| `-s[=force=true,fill=auto\|zero\|random]` | Strip debug info, COFF/Rich headers, symbol tables, build metadata. | `force=false`, `fill=auto` |
| `-c[=force=true,keep_resources=true\|false]` | Compact dead ranges, normalise section alignment, trim unused space. | `force=false`, `keep_resources=true` |
| `-o[=force=true,preserve_load_order=true\|false]` | Obfuscate: NULL-wipe section names, zero header metadata, zero-fill padding, scrub runtime strings. | `force=false`, `preserve_load_order=false` |
| `-r=pattern=…[,fill=zero\|random][,force=true]` | Overwrite bytes matching regex patterns. `pattern` accepts inline regex or a file path; multiple `-r` flags accumulate. | `fill=zero`, `force=false` |
| `-i=name=…,file\|data=…,password=…` | Insert a new AES-encrypted section. Provide exactly one of `file` or `data`. | — |
| `-l=file\|data=…,password=…` | Append an encrypted overlay payload after the image. | — |
| `-ei=name=…\|index=N[,password=…][,destination=PATH]` | Extract an inserted section by name or zero-based index. | — |
| `-el[=password=…][,destination=PATH]` | Extract the overlay payload. Defaults to `<input>.extracted`. | — |

> **`fill` modes:** `auto` picks zero for most fields and random for inter-section gaps; `zero` uses `0x00` everywhere; `random` uses cryptographic random bytes.

> **`force` mode:** enables aggressive, potentially breaking transforms intended for research (e.g. import table shuffling, segment reordering). Use with caution — force-mode changes may prevent the binary from executing.

## Examples

```bash
# Deep JSON analysis
gosstrip -a=format=json,mode=deep firmware.bin report.json

# Strip + compact + obfuscate (safe defaults)
gosstrip -s -c -o sample.bin hardened.bin

# Strip with random fill + compact + obfuscate
gosstrip -s=fill=random -c -o sample.bin hardened.bin

# Regex scrub from a pattern file
gosstrip -r=pattern=patterns.txt,fill=random teardown.bin

# Insert encrypted section + append overlay
gosstrip -i=name=.ops,data=0x414243,password=secret beacon.bin
gosstrip -l=file=payload.bin,password=overlaypass beacon.bin

# Extract section and overlay
gosstrip -ei=name=.ops,password=secret,destination=section.bin beacon.bin
gosstrip -el=password=overlaypass,destination=overlay.bin beacon.bin
```

## Architecture

```
main.go ─── CLI flags & pipeline orchestration
  │
  ├── common/   shared types, crypto, pipeline engine, analysis, reporting
  │
  ├── perw/     PE read/write, strip, compact, obfuscate, insert, overlay, extract
  │
  └── elfrw/    ELF read/write, strip, compact, obfuscate, insert, overlay, extract
```

| Path | Description |
|------|-------------|
| `main.go` | CLI entry point — flag parsing, pipeline construction, result rendering. |
| `common/` | Shared infrastructure: pipeline engine, crypto (AES-GCM), binary fill, analysis helpers, stage errors, report builder, regex guard. |
| `perw/` | PE format: readers/writers, strip rules, section compaction, header obfuscation, import table handling, section insertion, overlay management. |
| `elfrw/` | ELF format: readers/writers, strip rules, header compaction, program header obfuscation, dynamic symbol handling, section insertion, overlay management. |
| `test/` | Integration tests, CLI matrix scripts, cross-compilation fixture builders. |
| `testfiles/` | Small C/Go programs compiled during tests as PE and ELF fixtures. |
| `docs/` | Technique documentation (see below). |

### Documentation

| Document | Topic |
|----------|-------|
| `docs/STRIPPING_TECNIQUE.md` | What gets stripped and why — COFF, Rich Header, debug directories, symbol tables. |
| `docs/COMPACT_TECNIQUE.md` | Dead-range compaction and section alignment normalisation. |
| `docs/OBFUSCATION_TECNIQUE.md` | Obfuscation passes: section names, padding, headers, imports, runtime strings. |
| `docs/REGEX_REMOVAL.md` | Regex-based byte scrubbing with fill modes. |
| `docs/INSERT_OVERLAY.md` | Encrypted section insertion and overlay appending. |
| `docs/ANALYSIS_MODES.md` | Simple vs deep analysis, JSON output format. |
| `docs/RESEARCH_AV_EVASION.md` | AV/EDR evasion research — external tool comparison, heuristic analysis, prioritised improvements. |
| `docs/OPERATIONS_TESTING.md` | Test strategy and operation coverage. |

Reference strip/obfuscation rule lists: `docs/pe_strip.txt`, `docs/elf_strip.txt`, `docs/pe_obfuscation.txt`, `docs/elf_obfuscation.txt`.

## Tests

```bash
# Full suite
go test ./...

# Unit tests for a specific package
go test ./perw -run TestName -v

# CLI matrix (compiles fixtures, runs full PE/ELF pipeline)
bash test/cli_matrix.sh
```

Integration tests compile C/Go fixtures and exercise the complete analyse → strip → compact → obfuscate → regex → insert → overlay → extract pipeline in both default and force modes. Tests skip gracefully when prerequisites (`gcc`, `wsl`) are unavailable.

## Contributing

See `AGENTS.md` for the development workflow, coding conventions, and testing expectations.

## License

[MIT](LICENSE)
