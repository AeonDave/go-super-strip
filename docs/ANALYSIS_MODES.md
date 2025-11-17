# ANALYSIS MODES & OUTPUT FORMATS

The `-a` flag inspects a PE or ELF binary without modifying it. This document describes how the analyzer works, what the “simple” and “deep” modes show, and how the JSON formatter is produced.

## 1. Modes & Flags

```
gosstrip -a[=format=json,mode=deep] <input> [output]
```

- `mode=simple` (default): curated summary meant for CI logs and manual inspection.
- `mode=deep`: legacy verbose dump that mirrors the original analyzers, useful when hunting parser bugs.
- `format=text` (default) prints the report to stdout unless an `<output>` file is provided.
- `format=json` wraps the same report inside a JSON envelope (`{"file":"...", "format":"PE", "mode":"simple", "text_report":"..."}`) so automated tooling can parse it.

Analyze runs alone—it cannot be combined with other features.

## 2. PE Analyzer Highlights

Implementation: `perw/analyze.go`.

### 2.1 Binary Summary

- File type, architecture, entry point, subsystem, security directory presence, signed/unsigned status.
- Header hygiene warnings (timestamps, checksum, Rich header presence).

### 2.2 Section Table

- Name, RVA, raw size, entropy, characteristics.
- Flags unexpected names as “(obfuscated)” instead of fatal errors so obfuscation can keep working.
- Shows canonical order violations and overlapping ranges.

### 2.3 Data Directories

- Import/Export/TLS/Load Config summary: counts, anomalies, mismatched RVAs.
- Resource tree summary (levels, icon counts, manifest hints). Force strip/compact may remove some entries; analyzer will highlight missing directories.

### 2.4 Entropy & Regex Findings

- Section entropy bars give a quick read on compression/packing.
- Lists literal strings (Go build IDs, compiler banners) still present. This is useful before/after regex removal.

### 2.5 Deep-only Extras

- Full import/export lists, debug directory records, digital signature metadata, relocation entries with RVAs.
- Raw hex previews when parser detects corrupted structures.

## 3. ELF Analyzer Highlights

Implementation: `elfrw/analyze.go`.

### 3.1 Binary Summary

- ELF class, endianness, machine, ABI, entry point, interpreter path.
- Flags mismatched ABI signatures or unsupported features (e.g., CHERI).

### 3.2 Program Headers

- Per-segment file vs. memory sizes, permissions, and padding. Detects oversize gaps that compact could reclaim.
- Warns when PT_INTERP/PT_DYNAMIC/PT_TLS are missing even though the binary appears dynamically linked.

### 3.3 Section Inventory

- Each section’s type, flags, offset, and size with warnings for overlaps or off-end ranges (common in Go builds with packed debug data).
- Highlights stripped names and prints “(obfuscated)” tags when names no longer match canonical expectations.

### 3.4 Symbol/Relocation Overview

- Count of static/dynamic symbols, relocations per type, TLS usage, Go metadata presence (`.gopclntab`, `.typelink`, `.itablink`).
- Notes whether compact successfully removed typelink sections when requested.

### 3.5 Note & Build Info

- Summaries for `.note.gnu.build-id`, `.note.go.buildinfo`, `.note.gnu.property`.
- Reports when notes are missing after force strip/compact.

### 3.6 Deep-only Extras

- Full section table dump, relocations grouped by segment, dynamic dependency list, symbol names (if not obfuscated).
- Raw hex windows for corrupted sections.

## 4. JSON Output

- When `format=json`, we capture the textual analyzer output and insert it into a JSON document along with metadata (mode, timestamp, warnings, parsed file type).
- Consumers can parse the JSON to fetch warnings/errors while displaying the existing table to users.

## 5. Error Handling

- If parsing fails, analyze still emits a JSON/text fallback containing the raw error plus whatever partial information was gathered.
- When a binary has been intentionally broken (force obfuscation), analyze reports `Overall Status: degraded` but keeps running to show as much data as possible.

## 6. Manual Validation

Use `tests/cli_matrix.sh` to capture before/after analyze logs automatically. For ad-hoc checks:

```bash
./gosstrip -a testfiles/simple_go.exe > logs/pe_analyze.txt
./gosstrip -a=format=json,mode=deep testfiles/simple_elf > logs/elf_analyze.json
```

Review the warnings section to confirm new strip/compact features show up as expected.
