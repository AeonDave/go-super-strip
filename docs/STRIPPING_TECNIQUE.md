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

### Fill overrides

The CLI now accepts `-s=fill=auto|zero|random`. In `auto` (default) we use the rule-defined fill mode from `strip_types.go`. Setting `zero` forces deterministic zero filling for every section/pattern, while `random` forces pseudorandom data (useful when zero blocks are too obvious). The override hits both section wipes and the built-in regex scrubbers that run as part of strip; standalone regex runs use the dedicated `-r=fill=…` knob.

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
	- Packed guard: COFF `TimeDateStamp` is skipped when `p.IsPacked && !force`.
- **Rich header** (DanS...Rich block) is detected and blanked in-place.

### 3.3 Directory Sanitization

- Debug directory: zeroes the debug data and clears the Debug directory entry.
- Resource directory: zeroes timestamp + version in the resource root header.
- Load Config: zeroes timestamp + version in the load config header.
- Import directory metadata: only in `force` (descriptor timestamps/forwarder chain).

### 3.4 Pattern Scrubbing

- Regex rules from `perw/strip_types.go::GetRegexStripRules()` cover build IDs, compiler banners, PDB paths, user paths, and packer signatures.
- Each match is replaced with zeros (or random when `fill=random` was requested upstream). We never change length to avoid shifting offsets.
- Protected ranges (when `force=false`): entrypoint page, import directory/IAT, and packed payload sections (high-entropy or RWX-large).
- UPX header patterns are allowed to bypass packed payload protection to restore historical behavior.

### 3.5 Force-only Extras

- Force mode enables stripping of risky sections and import directory metadata.

## 4. ELF Techniques

Implementation lives in `elfrw/`:

### 4.1 Section Classification

- `elfrw/strip_types.go` groups sections as Debug (.debug*, .zdebug*, .gdb_index), Toolchain (.comment, .note.*, `.gcc_except_table`), Runtime Metadata (.gopclntab, .typelink, build info), and Critical (.text, .data, .rodata, GOT/PLT, dynamic sections).
- Default stripping targets Debug/Toolchain categories plus `.note.gnu.build-id` when it is duplicated elsewhere.
- Force mode allows pruning relocation helpers, `.eh_frame`, `.gcc_except_table`, and loader notes—only if the ELF is statically linked or we can rebuild the structures.

### 4.2 Header & Note Cleanup

- ELF header padding (EI_PAD bytes) and EI_ABIVERSION are zeroed; `e_flags` is zeroed.
- PT_NOTE segment payloads are zeroed, but only when section headers are available (skip when packed/no sections).

### 4.3 TLS & Dynamic Data

- Default mode avoids touching loader-critical dynamic sections; risky removals are gated behind `force`.

### 4.4 Pattern Scrubbing

- Regex rules mirror the PE set and include Go module paths, build IDs, compiler banners, and absolute source directories.
- Protected ranges include critical sections and PT_INTERP, plus `.shstrtab` via a dedicated guard.

### 4.5 Fill Mode Coordination

- Strip honors the CLI-level `fill` option by calling `common.ZeroFillData` or `common.RandomFillData`.

## 5. Validation & Instrumentation

After each strip pass we:

- Emit an `OperationResult` summarizing counts per category and warnings for skipped sections.
- Flag which sections are now “eligible for compaction” (size zero, marked by `MarkSectionStripped`). Compact relies on this metadata to know what it may delete.
- Re-run lightweight analyzers to ensure entry points still resolve to valid sections.

Unit coverage: see `perw/operations_test.go`, `elfrw/operations_test.go`, and the CLI matrix script (`test/cli_matrix.sh`) for end-to-end verification. These tests cover default vs. force and multiple fill strategies.
