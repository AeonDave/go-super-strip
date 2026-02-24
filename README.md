# go-super-strip

A cross-platform binary transformation toolkit for ELF and PE executables. It chains stripping, compaction, obfuscation, regex-based scrubbing, payload insertion, overlay management, extraction, and polymorphic packing into a single CLI.

## Overview
- Works on Linux and Windows hosts while targeting both ELF and PE binaries with the same commands.
- Operations run in a deterministic pipeline so every mutation is analyzable and reproducible.
- Supports destructive "force" modes for research scenarios and safe defaults for production hardening.
- Advanced packer generates polymorphic stubs, optional encryption/compression, and fileless execution modes.

## Installation
```bash
git clone https://github.com/AeonDave/go-super-strip
cd go-super-strip
# Linux
go build -o gosstrip

# Windows
go build -o gosstrip.exe
```

## CLI Overview
```
gosstrip -a[=format=json,mode=deep] <input> [output]
gosstrip [-s[=...]] [-c[=...]] [-o[=...]] [-r=...] [-i=...] [-l=...] [-ei=...] [-el=...] [-p=...] <input> [output]
gosstrip -v
```
- `-a` (analyze) runs alone and optionally writes the report to `output`.
- `-v` prints the CLI version and exits.
- When multiple operations are provided the CLI enforces the canonical order below and mutates `input` in-place unless an `output` path is supplied.

```
analyze (optional)
  |
strip (-s)
  |
compact (-c)
  |
obfuscate (-o)
  |
regex (-r)*   (*can appear multiple times)
  |
insert section (-i)
  |
overlay (-l)
  |
extract section (-ei)
  |
extract overlay (-el)
  |
pack (-p)
```

## Feature Flags & Options
| Flag | Purpose | Options |
|------|---------|---------|
| `-a[=format=text|json,mode=simple|deep]` | Analyzer for PE/ELF metadata. JSON output is available only for `mode=deep`. | Defaults: `format=text`, `mode=simple`. |
| `-s[=force=true/false,fill=auto|zero|random]` | Strips debug information, COFF/Rich headers, symbol tables, etc. | `force=false` (alias: `f`), `fill=auto` by default. |
| `-c[=force=true/false,keep_resources=true/false]` | Trims dead ranges and normalizes headers. | `force=false` (alias: `f`), `keep_resources=true` (aliases: `keep-resources`, `keepresources`) preserves PE `.rsrc` data unless disabled. |
| `-o[=force=true/false,preserve_load_order=true/false]` | Randomizes section names, fills padding gaps, and shuffles select metadata. | `force=false` (alias: `f`); `preserve_load_order` applies to ELF program headers. |
| `-r=pattern=…[,pattern=…][,fill=zero|random][,force=true/false]` | Overwrites bytes that match one or more regexes. | `pattern` accepts literal regexes or file paths; default fill is zeroes. Multiple `-r` flags accumulate patterns. `force=true` disables protected ranges. |
| `-v` | Print CLI version and exit. | No options. |
| `-i=name=…,file|data=…,password=…` | Inserts a new encrypted section. | Provide exactly one of `file` or `data` (ASCII or `0x` hex). `password` accepts ASCII or hex. Names longer than 8 chars are truncated for PE. |
| `-l=file|data=…,password=…` | Appends an overlay payload after the executable image. | Same data/password rules as section insertion. |
| `-ei=name=…|index=N[,password=…][,destination=PATH]` | Extracts an inserted section by name or index (0-based). | One of `name` or `index` is mandatory. Output defaults to `<input>.extracted`. |
| `-el[=password=…][,destination=PATH]` | Extracts the overlay payload. | Output defaults to `<input>.extracted`. |
| `-p=key=value,.` | Packs the executable with compression, encryption, polymorphism, and in-memory strategies. | See **Feature Details -> Pack** for every option (compression, encryption, padding, junk density, in-memory modes such as `memfd`, `process_hollowing`, `self_injection`, `params`, cleanup, verbosity, etc.). |

## Feature Details
### Analyze (`-a`)
- Modes: `simple` (concise, emoji-free summary) and `deep` (verbose tables, JSON support).
- `format=json` always implies `mode=deep`.
- Writing to `output` preserves a copy for later audits.

### Strip (`-s`)
- Removes debuginfo, symbol tables, DWARF, Rich headers, and customizable sections.
- `force=true` ignores safe lists (e.g., drops PE relocation/exception data).
- `fill=auto` respects per-rule fill requirements, while `zero` or `random` override the wipe pattern.

Flow (ASCII, PE)
```
[Read PE] -> [Section wipe] -> [Header scrub] -> [Directory scrub] -> [Regex scrub] -> [Save]
```

Flow (ASCII, ELF)
```
[Read ELF] -> [Section wipe] -> [Header scrub] -> [Regex scrub] -> [Save]
```

- Safe defaults: skips loader tables (PT_INTERP/relocations), preserves Go runtime tables (`.gopclntab`) and PE resources/manifests (`.rsrc`) unless `force=true`. Regex scrubbing avoids string tables/interpreter paths unless forced.
- Force mode: required for relocation/exception stripping, resource removal, and any loader-facing mutation that can break execution.

### Compact (`-c`)
- Reflows headers, truncates trailing padding, and rebuilds ELF section/header tables.
- `force=true` removes relocation helpers (e.g., ELF SHT) even if downstream tooling expects them.
- `keep_resources=false` allows `.rsrc` to be removed from PE binaries.

Flow (ASCII, PE)
```
[Read PE] -> [Identify removable] -> [Remove/trim] -> [Recalc headers] -> [Save]
```

Flow (ASCII, ELF)
```
[Read ELF] -> [Identify removable] -> [Remove/trim] -> [Rebuild SHT] -> [Validate] -> [Save]
```

### Obfuscate (`-o`)
- Renames sections, fills padding gaps, tweaks header metadata, and reorders select tables.
- `force=true` enables higher-risk mutations (e.g., import thunk shuffling, ELF segment relocation).
- `preserve_load_order=true` keeps ELF PT_LOAD ordering stable when obfuscating program headers.

Flow (ASCII, PE)
```
[Read PE] -> [Rename sections] -> [Fill gaps] -> [Runtime strings] -> [Header metadata] -> [Imports] -> [Save]
```

Flow (ASCII, ELF)
```
[Read ELF] -> [Rename sections] -> [Header fields] -> [Program headers] -> [Dynsym] -> [Save]
```

### Regex (`-r`)
- Each `pattern=` token can contain a literal regex or a path to a newline-separated rules file (blank lines and `#` comments ignored).
- Multiple `pattern=` fragments on one flag or across repeated `-r` flags accumulate.
- `fill=random` uses CSPRNG data; `fill=zero` (default) restores deterministic hashes.
- `force=true` disables protected ranges (entrypoint/IAT for PE; PT_INTERP/PT_LOAD and `.shstrtab` for ELF).
- Regex evaluation has a timeout and max-match cap to guard against runaway patterns.

### Section Insert (`-i`)
- Adds a new section for implants, config blobs, etc.
- `data=` accepts ASCII or `0x` prefixed hex; `file=` embeds contents verbatim.
- `password=` encrypts the section with the project’s symmetric helper; omit it for plaintext.

### Overlay Insert (`-l`)
- Similar to section insert but stored after the executable image so the original layout stays intact.
- Password and data/file semantics match `-i`.

### Section Extract (`-ei`)
- Choose the target section by `name=` (preferred when obfuscation keeps the label) or `index=N` when the name was randomized.
- `destination=` overrides the default `<input>.extracted` path.
- `password=` decrypts payloads created with `-i` (auto-detects ASCII vs hex passwords).

### Overlay Extract (`-el`)
- Dumps the appended overlay; optionally decrypts via `password=`.
- `destination=` behaves like `-ei`.

### Pack (`-p`)
The packer rewrites the binary into a self-extracting Go stub plus encrypted payload.

**Compression & Encryption**
- `compression=zlib|none` (alias `comp`) and `level=0-9` (ignored when compression is `none`).
- `encryption=xor|aes-256-gcm|chacha20|none` (aliases `encrypt`, `encr`). AES/ChaCha automatically create keys/nonces when none are provided. Accepted aliases for algorithms: `aes`, `aes-gcm`, `aes256` → `aes-256-gcm`; `chacha`, `chacha20poly1305` → `chacha20`.

**Polymorphism & Noise**
- `polymorphic=true/false` (alias `poly`). When true you can also tune:
  - `junkdensity=0.0-1.0` (alias `junk`)
  - `regperm=true/false`, `cfmutation=true/false`, `instrsubst=true/false`
- `padding=true/false` toggles random padding; padding sizes follow the defaults (512–4096 bytes) to avoid exposing custom fingerprints.
- Enabling polymorphism increases the stub size roughly in proportion to the density/mutation flags above; leave it disabled (or set low density) when you need the smallest stub.

**Execution & Telemetry**
- `inmemory=off|auto|memfd|process_hollowing|self_injection` (alias `inmem`)
  - `auto` selects `memfd` on Linux and `process_hollowing` on Windows.
  - `memfd` (Linux only, selected by `auto`): uses `memfd_create` + `fexecve` to run without touching disk; falls back to temp file if the syscall is unavailable.
  - `process_hollowing` (Windows only): spawns a suspended sacrificial process, calls `NtUnmapViewOfSection`, writes the payload with `WriteProcessMemory`, fixes the thread context, and resumes execution.
  - `self_injection` (Windows only): pins a copy of the payload, patches ETW/AMSI, allocates executable memory with `NtAllocateVirtualMemory`, maps the PE image (PE32 and PE32+), resolves imports and relocations, and launches the entry point via `NtCreateThreadEx` inside the current process. Falls back to temp file on failure.
- `params="ascii command"` appends a default command line when the payload is executed. These arguments run before user-supplied CLI args, so you can bake in sequences like `-sn 127.0.0.1 -oN output.txt`. Strings with spaces should be quoted.
- `cleanup=true/false` deletes temporary files when not running in-memory.
- `verbose=true/false` (alias `v`) prints the pack configuration before building the stub.
- `output` still follows the CLI positional argument—`-p` mutates `input` unless an `output` path is provided.

**Polymorphic Techniques**
During packing, technique tags are emitted in the CLI result (e.g., `stub_variant_multi_pass`, `forward_iteration`, `padding_entropy`, `elf_pad_randomization`). Use them to confirm coverage across builds.

**In-Memory Strategies**

| OS | Mode | Behavior |
|----|------|----------|
| Any | `off` / `base_exec` | Writes the decrypted payload to a temp file and executes it. Temp file is removed when `cleanup=true`. |
| Linux | `auto` / `memfd` | Uses `memfd_create` + `fexecve` for fileless execution; falls back to temp file if the syscall is unavailable. |
| Windows | `auto` / `process_hollowing` | Spawns a suspended sacrificial process, unmaps its image via `NtUnmapViewOfSection`, writes the payload and fixes the thread context, then resumes execution. |
| Windows | `self_injection` | Pins the payload in the current process, patches ETW + AMSI, allocates executable memory via `NtAllocateVirtualMemory`, maps the PE image (PE32 and PE32+), resolves imports/relocations, and launches via `NtCreateThreadEx`. Falls back to temp file on failure. |

Regardless of mode, the stub compiler includes only the routines required for the resolved architecture/strategy, so unused loaders never ship in the final binary. Compression/encryption/padding operate solely on the payload blob; polymorphism is the only option that physically enlarges the stub itself.

## Examples
### Analyze
```bash
gosstrip -a firmware.bin > firmware.report.txt
```

### Strip + Compact + Obfuscate
```bash
gosstrip -s=fill=random -c -o sample.bin hardened.bin
```

### Regex Removal
```bash
# patterns.txt contains newline-separated regexes (comments start with #)
gosstrip -r=pattern=patterns.txt,fill=random teardown.bin
```

### Section & Overlay Insertion
```bash
gosstrip -i=name=.ops,data=0x414243,password=fieldnotes beacon.bin
gosstrip -l=file=payload.bin,password=overlaypass beacon.bin
```

### Section & Overlay Extraction
```bash
gosstrip -ei=name=.ops,password=fieldnotes beacon.bin extracted_section.bin
gosstrip -el=password=overlaypass beacon.bin overlay_dump.bin
```

### Full Pipeline + Pack
```bash
gosstrip -s -c -o -r=pattern='UPX!' -i=name=.intel,data=SECRET \
        -l=file=loot.bin,password=stash \
        -p=compression=zlib,encryption=chacha20,polymorphic=true,inmemory=memfd \
        agent.bin agent.packed
```

## Manual Pack Verification
`test/manual_pack_flow.ps1` builds PE/ELF fixtures, runs analyze→pack→analyze for each supported in-memory mode (`process_hollowing`, `self_injection`, `memfd`, etc.), executes the resulting binaries, and captures the console output. When additional fixtures or parameterized commands are needed you can point the script at them via the `GOSSTRIP_PACK_PARAMS_*` environment variables (fixture path, arguments, expected output). On Windows the harness automatically uses `gosstrip.exe`; launching the CLI without the `.exe` suffix triggers the “Choose an app” dialog, so keep the extension when running binaries directly.

## FAQ
**Does `force=true` break binaries?**  Force modes deliberately remove safety checks (e.g., stripping relocations). Use them only when a broken output is acceptable for research.

**How do regex rule files work?**  Provide a plain-text file containing one regex per line. Blank lines and lines that start with `#` are ignored. Mix file-based and inline patterns freely.

**Can I run only a single operation?**  Yes—omit other flags. Every scenario should still begin and end with `gosstrip -a=mode=deep` when you gather logs.

**Why do I still see obfuscation warnings in analyze logs?**  Renamed sections/imports are reported as "unexpected" by design; they confirm obfuscation was applied.

**Where are operation logs stored?**  CLI matrix runs write to `test/logs/cli_matrix_<timestamp>/...`, and the pack matrix harness writes to `test/logs/pack_matrix_<timestamp>/...`.

## Tests

### Quick run
```bash
go test ./...
```
Runs all unit tests, fixture builders, and the pack matrix unit harness.

### Build test fixtures (Windows PE + Linux ELF)

Before running integration tests you need the compiled test binaries.

**Windows PE payloads** (MinGW or MSVC required):
```powershell
cd testfiles-generic
.\build_all_payloads.ps1              # builds all Windows EXEs (MinGW + MSVC + Go)
.\build_all_payloads.ps1 -MinGWOnly   # MinGW only
.\build_all_payloads.ps1 -MSVCOnly    # MSVC only
.\build_all_payloads.ps1 -GoOnly      # Go EXEs only
```

**Linux ELF payloads** (requires WSL with `gcc`/`g++`; Go cross-compiles from the Windows host):
```powershell
.\build_all_payloads.ps1 -Linux       # builds all Linux ELFs into out/linux/
.\build_all_payloads.ps1 -Linux -GoOnly  # Linux + Windows Go only (no C/C++ needed)
```

Outputs land in:
- `testfiles-generic/*.exe` — Windows PE executables
- `testfiles-generic/out/linux/` — Linux ELF executables (picked up automatically by `TestCLIFixtureMatrix`)
- `testfiles-generic/out/linux/so/` — Linux shared objects (`.so`), not used in execution tests

### Go integration tests — fixture matrix
```bash
# All fixture matrix tests (NoInPlaceMutation + ExecutesAfterSCO)
go test ./test/... -v -run TestCLIFixtureMatrix -timeout 300s

# Only check binaries survive all flag combinations (no execution)
go test ./test/... -v -run TestCLIFixtureMatrix_NoInPlaceMutation

# Strip+compact+obfuscate then actually execute via WSL / native OS
go test ./test/... -v -run TestCLIFixtureMatrix_ExecutesAfterSCO
```
`TestCLIFixtureMatrix_NoInPlaceMutation` covers every discovered fixture × 7 flag combos (`-s`, `-c`, `-o`, `-s -c`, `-s -o`, `-c -o`, `-s -c -o`) and verifies the original file is never mutated in-place.
`TestCLIFixtureMatrix_ExecutesAfterSCO` applies `-s -c -o`, then actually executes all non-UPX ELF binaries (via WSL on Windows) and PE binaries natively.

Fixtures are discovered automatically from:
- `testfiles/prebuilt/win/` — prebuilt PE fixtures
- `testfiles/prebuilt/linux/` — prebuilt ELF fixtures
- `testfiles-generic/out/linux/` — locally compiled ELF payloads (ignored when the directory doesn't exist)

### CLI matrix script (full PE/ELF pipeline)
```bash
bash test/cli_matrix.sh
```
Compiles PE/ELF fixtures and runs `analyze(deep) → strip(fill=zero/random) → compact → obfuscate → regex → insert → overlay → extract` in default and force modes. Logs land in `test/logs/cli_matrix_<timestamp>/`.

### Pack matrix
```powershell
pwsh test/pack_matrix.ps1
```
Builds platform CLIs, packs every compression/encryption/in-memory combination, then executes the packed binaries. Requires `x86_64-w64-mingw32-gcc`, `gcc`, and WSL for ELF execution on Windows. Logs land in `test/logs/pack_matrix_<timestamp>/`.

Review the generated logs—especially analyzer summaries at the start and end—to catch regressions before shipping changes.

## Architecture
Flow (ASCII)
```
[CLI] -> [Pipeline]
           |
           +-> [perw]  (PE read/write + transforms)
           |
           +-> [elfrw] (ELF read/write + transforms)
           |
           +-> [pack]  (stub builder + payload wrap)
```

| Path | Description |
|------|-------------|
| `main.go` | CLI entry point, flag parsing, pipeline orchestration. |
| `perw/` | PE readers/writers, strip/obfuscation helpers, overlay support. |
| `elfrw/` | ELF readers/writers, overlay inserters, WSL helpers. |
| `pack/` | Compression, encryption, polymorphic stub compiler, in-memory strategies. |
| `test/` | Cross-platform integration tests, CLI matrix, pack matrix, fixture builders. |
| `docs/` | Technique deep dives (stripping, compaction, obfuscation, packing, etc.). |
| `testfiles/` | Prebuilt PE and ELF fixtures used by integration tests. |
| `testfiles-generic/` | C, C++, and Go sources for re-compilable PE/ELF test payloads. Run `build_all_payloads.ps1` (with `-Linux` for ELF via WSL) to populate `out/linux/` and the root directory. |

```
gosstrip/
|-- main.go
|-- perw/              (PE utilities)
|-- elfrw/             (ELF utilities)
|-- pack/              (packer + stubs)
|-- test/              (integration + scripts)
|-- docs/              (technique guides)
|-- testfiles/         (prebuilt PE/ELF fixtures)
`-- testfiles-generic/ (C/C++/Go sources + build script)
```
Use `docs/` for methodology deep dives and `AGENTS.md` for contributor workflow expectations.