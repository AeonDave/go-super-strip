# COMPACTION TECHNIQUES (PE & ELF)

This guide explains how the `-c` step physically shrinks binaries after stripping. It covers section selection, gap removal, validation, and force-mode heuristics for both Portable Executable (PE) and ELF targets.

## 1. Goals

1. Remove zeroed sections flagged by `strip`.
2. Collapse unused padding between sections/segments.
3. Optionally wipe overlay data once Authenticode and other signatures are removed.
4. Keep entry points, imports, and runtime data valid—even under `force=true` (edge cases excepted).

Compaction runs immediately after stripping in the canonical pipeline.

## 2. Options

- `keep_resources=true`: ensures Windows resources survive unless explicitly disabled.
- `force=true`: enables aggressive trimming (e.g., relocations, loader notes, TLS tables, Section Header Table removal on ELF).

All compaction passes zero out the targeted data before truncating it, so we no longer expose a user-facing `fill` toggle.

## 3. PE Compaction

Key code lives in `perw/compact.go`.

### 3.1 Section Selection

- We re-use strip metadata: sections marked `Stripped` become compaction candidates.
- If strip metadata is missing (e.g., user runs compact directly), we recompute rules via `identifyStripSections`.
- Default mode protects `.text`, `.data`, `.rdata`, `.idata`, `.edata`, `.reloc`, `.tls`, `.rsrc`, `.pdata`, `.xdata`, and any section referenced by a Data Directory entry.
- Force mode allows removal of `.reloc`, `.pdata/.xdata`, `.tls`, `.rsrc`, Load Config, Delay-Load tables, and even TLS directories referenced by the header once we zero the matching Data Directory entries.

### 3.2 Physical Removal

For each removable section (processed from highest index down):

1. Zero-fill the section data (defensive wipe).
2. Delete the file-aligned byte range from `RawData`.
3. Shift later section headers’ `PointerToRawData` values backward.
4. Rebuild section headers and update `NumberOfSections`, `SizeOfImage`, and `SizeOfHeaders`.
5. If required, adjust `AddressOfEntryPoint` when removed ranges precede it.

### 3.3 Gap & Overlay Trimming

- After sections disappear, we recompute `SizeOfImage` and `SizeOfHeaders`.
- Trailing zeros beyond the logical image end are truncated; if Authenticode is absent, overlay bytes are dropped.
- Packed guard: overlay trimming is skipped when `p.IsPacked` is true (packers may store data beyond the last section).

### 3.4 Directory Updates

- Any Data Directory pointing into a removed section is cleared (RVA/Size→0). We warn if the directory was critical (Import, Certificates, TLS) and removal only occurs under `force`.
- Import Table/IAT shuffling performed during obfuscation is preserved because compact rewrites lookups based on the new offsets, not by string matching.

### 3.5 Validation

- Confirms the entry point still falls inside an executable section.
- Optionally rehashes imports (debug builds) to ensure they point to real names.
- Emits byte counts: header shrinkage, section bytes saved, overlay trimmed.

## 4. ELF Compaction

See `elfrw/compact.go`.

### 4.1 Section Selection

- Preference is given to sections flagged by strip; otherwise `identifyCompactableSections` replicates the heuristics:
  - Safe removals: `.comment`, `.note.*`, `.symtab`, `.strtab`, `.debug*`, `.gdb_index`, `.go.buildinfo`, `.gopclntab` (if Go metadata analyzer confirms it is redundant).
  - Guarded removals: `.interp`, `.dynamic`, GOT/PLT, `.ctors/.dtors/.init_array/.fini_array`, `.eh_frame`, `.gcc_except_table`, `.data.rel.ro.*`, `.tbss`. These require either static linking or `force`.
  - Force also allows dropping `.shstrtab` and blank section headers, effectively hiding table names from analyzers.

### 4.2 Removal Algorithm

For each section:

1. Remove the raw bytes and adjust offsets in `SectionHeaders`.
2. Update any Program Header whose range sits after the gap.
3. Keep track of total bytes removed for reporting.

After all deletions:

- Rebuild the Section Header Table so indices stay in sync.
- Update `e.Header.Shoff`, `e.Header.Shnum`, and the string-table index. Force can set them to zero to mimic stripped kernels.

### 4.3 Segment Compaction

- When LOAD segments contain long zero pads, we consolidate them by moving trailing data forward and adjusting `p_offset/p_vaddr` while keeping alignment satisfied.

### 4.4 Overlay & Debug Data

- Data beyond the last LOAD segment is truncated; if overlay metadata exists we keep the data but shrink any zero tail.
- Go runtime metadata (typelink, itablink, go.buildinfo) can be removed even without strip as long as regex removal already wiped references; we validate via the analyzer before dropping them.

### 4.5 Validation

- Ensures entry point points into an executable segment and that interpreter / dynamic sections remain when required.
- In force mode we still keep PT_INTERP bytes when `hasInterpreter()` returns true to avoid breaking typical glibc binaries.
- Post-pass warnings explain why certain sections were kept (e.g., “kept .dynamic because DT_NEEDED entries remain”).

## 5. Force-mode Expectations

- Force should still produce runnable binaries on standard fixtures. We only accept breakage for intentionally malformed or highly specialized inputs (e.g., custom loaders, signed binaries with active certificates).
- Both PE and ELF emit explicit warnings if force removed something essential (imports, interpreter, TLS).

## 6. Testing

- Unit: `perw/compact_test.go`, `elfrw/compact_test.go`.
- CLI: `test/cli_cross_compile_test.go` runs strip→compact on compiled fixtures.
- Regression logging: `test/cli_matrix.sh` captures analyze→strip→compact→obfuscate flows and stores logs under `tests/logs/`.

Always run `go test ./...` plus `bash test/cli_matrix.sh` after modifying compaction logic so we cover both automated and manual flows.
