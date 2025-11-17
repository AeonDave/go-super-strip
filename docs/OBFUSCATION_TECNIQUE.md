# OBFUSCATION TECHNIQUES (PE & ELF)

The `-o` step disguises binaries after strip/compact have removed obvious markers. This document enumerates every technique implemented today, split by platform, and highlights the differences between default and `force` mode.

## 1. Design Principles

1. **Execution must remain correct** in default mode.
2. **Force mode** pushes harder (e.g., fake headers, metadata churn) yet should still keep normal fixtures runnable—breakage is tolerated only for exotic inputs.
3. All randomization uses the shared `common/rand` helper so tests can replay a seeded sequence.
4. PE and ELF share the same orchestration flow even if the per-format tricks differ.

## 2. Shared Building Blocks

- Section name randomization (with canonical sections allowed unless the user opts out).
- Symbol table scrubbing and relocation of orphaned names.
- Inline regex scrubber runs again to wipe literals that might have resurfaced.
- Overlay noise insertion (force only) to confuse tools reading beyond EOF.

## 3. PE Obfuscation (perw/obfuscate.go, perw/headers.go)

### 3.1 Section & Header Randomization

- Every section name can now be randomized; the previous guard that protected `.text/.data/.rdata` has been removed.
- We shuffle the section order (within logical groups) and adjust the RVA table so imports/exports keep working.
- Optional header tweaks: timestamp and linker version fields receive random but valid values, `SizeOfCode/Data` values are nudged within alignment tolerances, and subsystem versions drift slightly.

### 3.2 Import Table Obfuscation

- `randomizeImports()` reorders import descriptors and IAT entries, inserting trampolines so original ordinal lookups continue to work.
- Force mode can split the IAT into multiple fake tables and patch the thunk pointers at runtime via a small loader stub.

### 3.3 Debug Directory Pollution

- Additional CodeView records with random GUIDs are injected, pointing to fake PDB paths (`C:\build\<random>.pdb`).
- Force mode adds conflicting RSDS signatures plus zeroed age fields to make debuggers think multiple builds are mixed.

### 3.4 Instruction Padding

- Post-compact we walk executable sections and insert short padding sequences (`NOP`, `XCHG eax,eax`, `LEA reg,[reg]`) between functions, keeping alignment.
- Force mode can insert relative jumps to mini-trampolines, effectively reshuffling basic blocks without touching the entry point.

### 3.5 Overlay & Metadata Noise

- We optionally append encrypted junk blocks labeled as telemetry; analyzers that read to EOF see inconsistent sizes between headers and disk.
- Digital signature presence is left intact, but we skew certificate timestamps (force) to hinder deterministic analysis.

## 4. ELF Obfuscation (elfrw/obfuscate.go)

### 4.1 Section Descriptors

- Randomizes `.text/.data/.rodata` names (within ELF character limits) and rewrites the Section Header String Table to hide the mapping.
- Reorders non-critical sections and adjusts the section header table accordingly.

### 4.2 Symbol and String Tables

- Scrubs `.symtab`, `.dynsym`, `.strtab`, `.dynstr` entries by replacing human-readable names with random identifiers while keeping symbol lengths intact.
- Force mode also blanks relocation target names and forces PLT/GOT entries to reference stub trampolines.

### 4.3 Metadata Tampering

- Tweaks ELF header `e_ident` padding, abis, and version codes to mimic different compilers.
- Modifies `.note.gnu.build-id` contents and size, optionally duplicating them with conflicting data.
- Force mode injects synthetic `.note.*` entries referencing random vendors or CPU extensions.

### 4.4 Instruction Padding

- Similar to PE, we pad text segments with architecture-friendly no-ops (for x86_64: `nop`, `lea rdi,[rdi]`). The logic is alignment aware.
- Force mode can slide function bodies around by redirecting symbol entries to new offsets.

### 4.5 Loader Camouflage

- Adds bogus PT_NOTE segments referencing non-existent interpreters; default mode keeps PT_INTERP intact while force may duplicate it with misleading paths (yet still preserving the real interpreter to keep binaries executable).

## 5. Reporting

- The analyzer records renamed sections as “unexpected name (obfuscated)” rather than hard errors.
- Obfuscation results include counts for renamed sections, imports shuffled, debug records added, padding bytes inserted, and warnings if a loader stub was injected.

## 6. Testing

- Unit: `perw/obfuscate_test.go` ensures imports still resolve after shuffling; additional fixtures confirm debug directory pollution and instruction padding toggles.
- CLI: `tests/cli_matrix.sh` exercises analyze→obfuscate→analyze and strip→compact→obfuscate flows for both PE and ELF (default & force). Logs make it easy to confirm analyzers surface the expected “unexpected name” warnings instead of fatal errors.
- Always run `go test ./...` plus the matrix script when modifying obfuscation code.
