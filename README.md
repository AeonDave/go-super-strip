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
```
- `-a` (analyze) runs alone and optionally writes the report to `output`.
- When multiple operations are provided the CLI enforces the canonical order below and mutates `input` in-place unless an `output` path is supplied.

```
   analyze (optional)
        │
    strip (-s)
        ↓
  compact (-c)
        ↓
 obfuscate (-o)
        ↓
 regex (-r)*   (*can appear multiple times)
        ↓
insert section (-i)
        ↓
overlay (-l)
        ↓
extract section (-ei)
        ↓
extract overlay (-el)
        ↓
   pack (-p)
```

## Feature Flags & Options
| Flag | Purpose | Options |
|------|---------|---------|
| `-a[=format=text|json,mode=simple|deep]` | Analyzer for PE/ELF metadata. JSON output is available only for `mode=deep`. | Defaults: `format=text`, `mode=simple`. |
| `-s[=force=true/false,fill=auto|zero|random]` | Strips debug information, COFF/Rich headers, symbol tables, etc. | `force=false`, `fill=auto` by default. |
| `-c[=force=true/false,keep_resources=true/false]` | Trims dead ranges and normalizes headers. | `keep_resources=true` preserves PE `.rsrc` data unless disabled. |
| `-o[=force=true/false]` | Renames sections/symbols and randomizes tables. | Force enables aggressive renames. |
| `-r=pattern=…[,pattern=…][,fill=zero|random]` | Overwrites bytes that match one or more regexes. | `pattern` accepts literal regexes or file paths; default fill is zeroes. Multiple `-r` flags accumulate patterns. |
| `-i=name=…,file|data=…,password=…` | Inserts a new encrypted section. | Provide exactly one of `file` or `data` (ASCII or `0x` hex). `password` accepts ASCII or hex. Names longer than 8 chars are truncated for PE. |
| `-l=file|data=…,password=…` | Appends an overlay payload after the executable image. | Same data/password rules as section insertion. |
| `-ei=name=…|index=N[,password=…][,destination=PATH]` | Extracts an inserted section by name or index (0-based). | One of `name` or `index` is mandatory. Output defaults to `<input>.extracted`. |
| `-el[=password=…][,destination=PATH]` | Extracts the overlay payload. | Output defaults to `<input>.extracted`. |
| `-p=key=value,.` | Packs the executable with compression, encryption, polymorphism, and in-memory strategies. | See **Feature Details -> Pack** for every option (compression, encryption, padding, junk density, in-memory modes such as `memfd`, `process_hollowing`, `atomic_bombing`, `params`, cleanup, verbosity, etc.). |

## Feature Details
### Analyze (`-a`)
- Modes: `simple` (concise, emoji-free summary) and `deep` (verbose tables, JSON support).
- `format=json` always implies `mode=deep`.
- Writing to `output` preserves a copy for later audits.

### Strip (`-s`)
- Removes debuginfo, symbol tables, DWARF, Rich headers, and customizable sections.
- `force=true` ignores safe lists (e.g., drops PE relocation/exception data).
- `fill=auto` respects per-rule fill requirements, while `zero` or `random` override the wipe pattern.

### Compact (`-c`)
- Reflows headers, truncates trailing padding, and rebuilds ELF section/header tables.
- `force=true` removes relocation helpers (e.g., ELF SHT) even if downstream tooling expects them.
- `keep_resources=false` allows `.rsrc` to be removed from PE binaries.

### Obfuscate (`-o`)
- Renames sections/imports, shuffles metadata, and injects harmless noise.
- `force=true` enables high-risk path mutations (duplicate removal, custom entrypoints).

### Regex (`-r`)
- Each `pattern=` token can contain a literal regex or a path to a newline-separated rules file (blank lines and `#` comments ignored).
- Multiple `pattern=` fragments on one flag or across repeated `-r` flags accumulate.
- `fill=random` uses CSPRNG data; `fill=zero` (default) restores deterministic hashes.

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
- `compression=xz|lzma|none` and `level=0-9` (ignored when compression is `none`).
- `encryption=xor|aes-256-gcm|chacha20|none`. AES/ChaCha automatically create keys/nonces when none are provided.

**Polymorphism & Noise**
- `polymorphic=true/false` (alias `poly`). When true you can also tune:
  - `junkdensity=0.0-1.0`
  - `regperm=true/false`, `cfmutation=true/false`, `instrsubst=true/false`
- `padding=true/false` toggles random padding; padding sizes follow the defaults (512–4096 bytes) to avoid exposing custom fingerprints.
- Enabling polymorphism increases the stub size roughly in proportion to the density/mutation flags above; leave it disabled (or set low density) when you need the smallest stub.

**Execution & Telemetry**
- `inmemory=off|auto|memfd|process_hollowing|atomic_bombing|self_injection|stealth_loader|reflective_loader`
  - `auto` selects `memfd` on Linux and the safest architecture-aware Windows strategy (PE32/PE32+ binaries keep their native loaders).
  - `memfd` (`auto` on Linux) uses `memfd_create` + `fexecve` to run without touching disk; it falls back to temp files if the syscall is unavailable.
  - `process_hollowing` (Windows) spawns a suspended process, calls `NtUnmapViewOfSection`, writes the payload with `WriteProcessMemory`, fixes the context, and resumes the thread.
  - `atomic_bombing` splits the payload into atoms, reconstructs it via a hidden window callback, then injects it with the APC-based reflective loader.
  - `self_injection` reflectively maps the payload inside the current process (supports both PE32 and PE32+), fixes relocations/imports, and calls the entry point directly.
  - `stealth_loader` disables ETW/AMSI, locks the OS thread, disables GC, pins the payload buffer, allocates executable memory with `NtAllocateVirtualMemory`, and launches it with `NtCreateThreadEx` (no sacrificial process).
  - `reflective_loader` is an extremely small loader (inspired by go-loader/Doge-MemX) that pins/reflects the payload inside the current process and launches it via `NtCreateThreadEx` after disabling GC/OS thread migration.
- `params="ascii command"` appends a default command line when the payload is executed. These arguments run before user-supplied CLI args, so you can bake in sequences like `-sn 127.0.0.1 -oN output.txt`.
- `cleanup=true/false` deletes temporary files when not running in-memory.
- `verbose=true/false` prints the pack configuration before building the stub.
- `params="ascii command"` appends a default command line when the payload is executed. These arguments run before user-supplied CLI args, so you can bake in sequences like `-sn 127.0.0.1 -oN output.txt`.
- `cleanup=true/false` deletes temporary files when not running in-memory.
- `verbose=true/false` prints the pack configuration before building the stub.
- `output` still follows the CLI positional argument—`-p` mutates `input` unless an `output` path is provided.

**Polymorphic Techniques**
During packing, technique tags are emitted in the CLI result (e.g., `stub_variant_multi_pass`, `forward_iteration`, `padding_entropy`, `elf_pad_randomization`). Use them to confirm coverage across builds.

**In-Memory Strategies**

| OS | Mode | Behavior |
|----|------|----------|
| Linux | `off` | Writes decrypted payload to a temp file and executes it. |
| Linux | `auto` / `memfd` | Uses `memfd_create` + `fexecve` for fileless execution, falls back to temp file if the syscall fails. |
| Windows | `off` | Writes to `%TEMP%`, runs via normal process creation, then cleans up when `cleanup=true`. |
| Windows | `auto` / `process_hollowing` | Spawns a sacrificial process, unmaps it, and injects the payload before resuming the thread. |
| Windows | `atomic_bombing` | Splits the payload into atom-encoded chunks, rebuilds it via a hidden window, and delivers the bytes through the APC-based injector. |
| Windows | `self_injection` | Reflectively maps the payload inside the current process (available for both PE32 and PE32+). |
| Windows | `stealth_loader` | Disables ETW/AMSI, pins the payload buffer, allocates executable memory via `NtAllocateVirtualMemory`, and spawns with `NtCreateThreadEx` (no child processes). |
| Windows | `reflective_loader` | Minimal reflective loader (no sacrificial process). Disables GC, pins the payload buffer, and launches it inside the current process via `NtCreateThreadEx`. |

Regardless of mode, the stub compiler includes only the routines required for the resolved architecture/strategy, so unused loaders never ship in the final binary. Compression/encryption/padding operate solely on the payload blob; polymorphism is the only option that physically enlarges the stub itself.

### Automatic UAC Bypass
Every Windows stub attempts the well-known *fodhelper* elevation sequence before unpacking:
1. Query the current user with `NetUserGetInfo` to ensure the account has local-admin privileges (no always-on UAC prompts).
2. Create `HKCU\Software\Classes\ms-settings\shell\open\command`, set the default value to the packed stub path, and add an empty `DelegateExecute`.
3. Launch `fodhelper.exe` hidden via `cmd.exe /C fodhelper`. Because `fodhelper` auto-runs the registered handler with high integrity, the stub is relaunched elevated.
4. Clean up the registry keys and exit the original process.

If elevation fails (non-admin user, UAC constraints, etc.) the stub simply continues in the current integrity level. All in-memory strategies benefit from elevation when available (memory allocation APIs succeed more often and suspended-process creation avoids access-denied errors).

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
        -p=compression=lzma,encryption=chacha20,polymorphic=true,inmemory=memfd \
        agent.bin agent.packed
```

## Manual Pack Verification
`test/manual_pack_flow.ps1` builds PE/ELF fixtures, runs analyze→pack→analyze for each supported in-memory mode (`process_hollowing`, `atomic_bombing`, `memfd`, etc.), executes the resulting binaries, and captures the console output. When additional fixtures or parameterized commands are needed you can point the script at them via the `GOSSTRIP_PACK_PARAMS_*` environment variables (fixture path, arguments, expected output). On Windows the harness automatically uses `gosstrip.exe`; launching the CLI without the `.exe` suffix triggers the “Choose an app” dialog, so keep the extension when running binaries directly.

## FAQ
**Does `force=true` break binaries?**  Force modes deliberately remove safety checks (e.g., stripping relocations). Use them only when a broken output is acceptable for research.

**How do regex rule files work?**  Provide a plain-text file containing one regex per line. Blank lines and lines that start with `#` are ignored. Mix file-based and inline patterns freely.

**Can I run only a single operation?**  Yes—omit other flags. Every scenario should still begin and end with `gosstrip -a=mode=deep` when you gather logs.

**Why do I still see obfuscation warnings in analyze logs?**  Renamed sections/imports are reported as "unexpected" by design; they confirm obfuscation was applied.

**Where are operation logs stored?**  CLI matrix runs write to `test/logs/cli_matrix_<timestamp>/...`, and the pack matrix harness writes to `test/logs/pack_matrix_<timestamp>/...`.

## Tests
- `go test ./...` (unit tests, fixture builders, pack matrix unit harness)
- `bash test/cli_matrix.sh` (compiles PE/ELF fixtures, runs analyze→strip→compact→obfuscate→regex→insert→overlay→extract flows for default/force and fill zero/random)
- `pwsh test/pack_matrix.ps1` (builds platform CLIs, packs every compression/encryption/in-memory combination, then executes the packed binaries; requires `x86_64-w64-mingw32-gcc`, `gcc`, and WSL for ELF execution on Windows)

Review the generated logs—especially analyzer summaries at the start and end—to catch regressions before shipping changes.

## Architecture
| Path | Description |
|------|-------------|
| `main.go` | CLI entry point, flag parsing, pipeline orchestration. |
| `perw/` | PE readers/writers, strip/obfuscation helpers, overlay support. |
| `elfrw/` | ELF readers/writers, overlay inserters, WSL helpers. |
| `pack/` | Compression, encryption, polymorphic stub compiler, in-memory strategies. |
| `test/` | Cross-platform integration tests, CLI matrix, pack matrix, fixture builders. |
| `docs/` | Technique deep dives (stripping, compaction, obfuscation, packing, etc.). |
| `testfiles/` | Small C/Go sources compiled during tests. |

```
gosstrip
├── main.go
├── perw/   (PE utilities)
├── elfrw/  (ELF utilities)
├── pack/   (packer + stubs)
├── test/   (integration + scripts)
├── docs/   (technique guides)
└── testfiles/
```
Use `docs/` for methodology deep dives and `AGENTS.md` for contributor workflow expectations.
