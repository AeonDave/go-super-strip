# STRIPPING TECHNIQUES (PE & ELF)

This note documents how the `-s` operation rewrites Windows PE and Linux ELF binaries inside **go-super-strip**. It is intended for contributors who change `perw/strip.go`, `elfrw/strip.go`, or add new heuristics referenced by the CLI. Everything below is English-language, production-targeted, and mirrors the current feature set (no legacy compatibility layer).

## 1. Purpose and Pipeline Context

Stripping is the first step in the canonical workflow:

```
strip → compact → obfuscate → regex → insert → overlay → pack
```

During strip we **zero or random-fill** sensitive metadata in place, but we do not remove section headers yet—that happens in the compact stage. The goals are:

- Make binaries deterministic by removing timestamps, Rich headers, and debug markers.
- Hide build metadata (toolchain versions, usernames, host paths, etc.).
- Flag sections that compact may later delete.

## 2. Safety Modes

- **Default (safe)**: acts only on non-critical structures—debug symbols, DWARF/CodeView data, compiler notes, build IDs, Rich headers, TLS directories with zero callbacks, etc. Binaries must remain runnable.
- **Force (`-s=force=true`)**: expands the removal set to cover relocation tables, TLS records with live callbacks, ARM/SEH unwind data, and other loader-visible structures. We still gate each step behind runtime checks (e.g., only strip `.pdata` if no function table references remain).

Every action records a `StripAction` result so later stages (compact, analysis) can reason about what changed.

## 3. PE Techniques

All code lives under `perw/`:

### 3.1 Section Classification

- Rules defined in `perw/strip_types.go` categorize each section (Debug, Symbols, NonEssential, BuildInfo, Exception, TLS, Relocations, Certificates).
- Default mode removes only SAFE categories; force mode removes RISKY categories as well.
- Each match logs the rule, the source section, and the fill mode used.

### 3.2 Header Hygiene

`perw/strip.go` sanitizes fixed headers:

- **DOS stub** reserved words set to zero (except the initial stub message).
- **COFF header** timestamp zeroed; symbol table pointer cleared when table removed.
- **Optional header** clears checksum, loader flags that are unused, and Data Directory timestamps (Debug, LoadConfig, Resource root, Delay-Load entries).
- **Rich header** (DanS...Rich block) is detected and blanked with deterministic XOR so compaction can later drop it entirely.

### 3.3 Directory Sanitization

- For each Data Directory, `stripDataDirectoryIfRemovable` validates size/RVA mapping and fills the referenced data range with zeros while keeping the directory entry consistent (size reset to `0`).
- TLS: resets callbacks count and zero-fills callback array to break profilers; force mode additionally blanks the raw template.
- Load Config: wipes Guard CF checksum and instrumentation fields.
- Security Directory is untouched in default mode; force mode can zap it only when the binary is already unsigned.

### 3.4 Pattern Scrubbing

- Regex rules from `perw/strip_types.go::GetRegexStripRules()` cover `go1\.[0-9]+`, `Go build ID`, compiler version banners, `@(#)`, `PDB` paths, user home paths, `Program Files`, and known packer signatures.
- Each match is replaced with zeros (or random when `fill=random` was requested upstream). We never change length to avoid shifting offsets.

### 3.5 Force-only Extras

- Force mode zeroes `.reloc` to defeat import rebuilding tools (compact may later drop the table entirely).
- `.tls`, `.pdata`, `.xdata`, `.safeseh`, `.rsrc` are blanked only when `force` and the analyzer confirmed they are either empty or unused.
- Debug directories receive fake GUIDs so debuggers cannot trace the original PDB path.

## 4. ELF Techniques

Implementation lives in `elfrw/`:

### 4.1 Section Classification

- `elfrw/strip_types.go` groups sections as Debug (.debug*, .zdebug*, .gdb_index), Toolchain (.comment, .note.*, `.gcc_except_table`), Runtime Metadata (.gopclntab, .typelink, build info), and Critical (.text, .data, .rodata, GOT/PLT, dynamic sections).
- Default stripping targets Debug/Toolchain categories plus `.note.gnu.build-id` when it is duplicated elsewhere.
- Force mode allows pruning relocation helpers, `.eh_frame`, `.gcc_except_table`, and loader notes—only if the ELF is statically linked or we can rebuild the structures.

### 4.2 Header & Note Cleanup

- ELF header padding (EI_PAD bytes) is zeroed for deterministic builds.
- Program headers with `p_flags` inconsistent with their sections are normalized (e.g., remove `PF_W` from read-only segments).
- `.note.gnu.property`, `.note.go.buildinfo`, `.note.ABI-tag`, `.note.linker-build-id`, `.note.gnu.build-id`: the payload is blanked while lengths remain intact.
- Force mode optionally removes the Section Header String Table and rewrites the section names map to random ASCII for obfuscation.

### 4.3 TLS & Dynamic Data

- Default mode keeps `.dynamic`, `.dynsym`, `.dynstr`, `.gnu.version*` but zeroes timestamps/sonames.
- Force allows blanking `.interp`, `.dynamic`, `.init_array` entries for statically linked binaries (guarded by `hasInterpreter` and relocation count).

### 4.4 Pattern Scrubbing

- Regex rules mirror the PE set and include Go module paths, `build id`, GCC version banners, thin LTO metadata, glibc version strings, and absolute source directories. They are applied to all LOADable sections plus `.rodata`.

### 4.5 Fill Mode Coordination

- Strip honors the CLI-level `fill` option by calling `common.ZeroFillData` or `common.RandomFillData`. This ensures both PE and ELF share the same deterministic RNG seeding for reproducible tests.

## 5. Validation & Instrumentation

After each strip pass we:

- Emit an `OperationResult` summarizing counts per category and warnings for skipped sections.
- Flag which sections are now “eligible for compaction” (size zero, marked by `MarkSectionStripped`). Compact relies on this metadata to know what it may delete.
- Re-run lightweight analyzers to ensure entry points still resolve to valid sections.

Unit coverage: see `perw/operations_test.go`, `elfrw/operations_test.go`, and the CLI matrix script (`tests/cli_matrix.sh`) for end-to-end verification. These tests cover default vs. force and multiple fill strategies.
