# OBFUSCATION TECHNIQUES (PE & ELF)

The `-o` step disguises binaries after strip/compact have removed obvious markers. This document enumerates every technique implemented today, split by platform, and highlights the differences between default and `force` mode.

## 1. Design Principles

1. **Execution must remain correct** in default mode.
2. **Force mode** pushes harder (e.g., fake headers, metadata churn) yet should still keep normal fixtures runnable—breakage is tolerated only for exotic inputs.
3. All randomization uses the shared `common/rand` helper so tests can replay a seeded sequence.
4. PE and ELF share the same orchestration flow even if the per-format tricks differ.

## 2. Shared Building Blocks

- All obfuscation is performed in-place and preserves binary size/alignment.
- Each stage records an `OperationResult` so later steps can report what changed.

## 3. PE Obfuscation (perw/obfuscate.go)

### 3.1 Section Names

- Section names are randomized using a realistic name pool; duplicates are avoided.

### 3.2 Section Padding

- For adjacent sections with small gaps (<64 KB), the gap is filled with random bytes.

### 3.3 Runtime Strings

- Targeted replacements in data/rdata sections (same-length swaps):
	- `fprintf` → `foutput`
	- `printf` → `output`
	- `libgcc2.c` → `libsys2.c`
	- `WinMain` → `AppMain`

### 3.4 Header Metadata

- Always: randomize COFF `TimeDateStamp` and linker version fields.
- Force: randomize `Subsystem` and `DllCharacteristics` (mask-limited).

### 3.5 Import Table

- Reorders import descriptors.
- Force: also shuffles thunks.

### 3.6 Debug Directory Noise (force)

- Additional CodeView records with random GUIDs are injected, pointing to fake PDB paths (`C:\build\<random>.pdb`).
- Force mode adds conflicting RSDS signatures plus zeroed age fields to make debuggers think multiple builds are mixed.

### 3.7 Executable Padding

- Tail padding (VirtualSize < SizeOfRawData) is randomized.
- Force: replaces long zero runs with multi-byte NOP patterns.
- Packed guard: skipped when `p.IsPacked && !force`.

### 3.8 Overlay & Metadata Noise

- Not implemented in current PE obfuscation pipeline.

## 4. ELF Obfuscation (elfrw/obfuscate.go)

### 4.1 Section Descriptors

- Randomizes section names and rebuilds `.shstrtab`.

### 4.2 Program Headers

- PT_NOTE rotation, optional PT_LOAD reorder, alignment randomization, and non-loadable `p_paddr` randomization.
- Force: relocate PT_NOTE/PT_GNU_EH_FRAME segments within growth limits.

### 4.3 Dynamic Symbols

- `.dynsym` entries are shuffled and relocations are rewritten to match.
- Force: optional `.dynstr` scrambling for non-essential symbols.

### 4.4 Section/String Table Wiping

- Obfuscation keeps an in-memory cache of section names. Force mode takes advantage of this by zeroing `.shstrtab` right before `Save`, ensuring on-disk names are blank even though subsequent operations can still resolve indices.

### 4.5 Metadata Tampering

- Tweaks ELF header padding and reserved fields.

### 4.6 Instruction Padding

- Not implemented in current ELF obfuscation pipeline.

### 4.7 Loader Camouflage

- Not implemented beyond the PT_NOTE/segment operations above.

## 5. Reporting

- The analyzer records renamed sections as “unexpected name (obfuscated)” rather than hard errors.
- Obfuscation results include counts for renamed sections, imports shuffled, debug records added, padding bytes inserted, and warnings if a loader stub was injected.

## 6. Testing

- Unit: `perw/obfuscate_test.go` ensures imports still resolve after shuffling; additional fixtures confirm debug directory pollution and instruction padding toggles.
- CLI: `test/cli_matrix.sh` exercises analyze→obfuscate→analyze and strip→compact→obfuscate flows for both PE and ELF (default & force). Logs make it easy to confirm analyzers surface the expected “unexpected name” warnings instead of fatal errors.
- Always run `go test ./...` plus the matrix script when modifying obfuscation code.
