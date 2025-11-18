# go-super-strip

A comprehensive binary manipulation toolkit for ELF and PE executables with advanced polymorphic packing capabilities.

## Documentation

Detailed technique guides, including stripping, compaction, and obfuscation walkthroughs, now live under [`/docs`](docs/).

## Features

### Core Operations
- **Analysis**: Deep inspection of PE/ELF file structures and sections
- **Stripping**: Remove debug symbols and unnecessary metadata
- **Compaction**: Reduce file size by removing non-essential sections
- **Obfuscation**: Apply techniques to hinder reverse engineering
- **Section Insertion**: Add custom encrypted sections to binaries
- **Overlay Management**: Append encrypted data beyond executable sections
- **Pattern Removal**: Strip bytes matching custom regex patterns
- **Polymorphic Packing**: Generate unique executable variants with identical functionality

### Polymorphic Packing

Status
- Advanced multi-variant polymorphism is integrated: a random stub variant is injected into the compiled stub at build time and anchored via init(), producing per-build unique binaries. Safe post-compile tweaks (e.g., ELF EI_PAD entropy) are also applied where applicable.
- In-memory execution is available (Linux: memfd_create; Windows: process hollowing) with automatic fallbacks to temporary files when needed.
- The packer prints the exact polymorphic technique tags it applied in the output details, so you can verify what was used for each build.

## Installation

```bash
git clone https://github.com/AeonDave/go-super-strip
cd go-super-strip
go build -o gosstrip
```

## Usage

### Command Syntax

```
gosstrip -a[=format=json,mode=deep] <input> [output]

gosstrip [ -s[=key=value,...] -c[=key=value,...] -o[=key=value,...] -r=pattern=rx[,pattern=rules.txt][,fill=random] -i=... -l=... -p=key=value,... ] <input> [output]
```

- `-a` (analyze) runs alone and supports optional output redirection.
- Pipeline operations always execute in canonical order: strip → compact → obfuscate → regex → insert → overlay → pack. CLI flags can appear only once (regex may repeat) and must respect this order.
- Provide `<output>` to write all edits to a copy; omit it to mutate the input file in place (packing follows the same rule).

### Feature Flags & Options

| Flag / Feature             | Purpose                                                                                                      | Accepted options / notes                                                                                                                                         |
|----------------------------|--------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-a[=format=json,mode=deep]` | Analyze PE/ELF structures and emit either text (default) or JSON. With `<output>` the report is written to disk. | `format` = `text` or `json`. `mode` = `simple` (concise summaries) or `deep` (legacy verbose analyzer). Analysis cannot be combined with other features.        |
| `-s[=force=true,fill=auto]`          | Strip debug symbols, Rich headers, DWARF data, etc.                                                          | `force` (bool, default `false`) permits aggressive removals. `fill` overrides how stripped regions are wiped: `auto` (respect rule), `zero`, or `random`.                                                                                                   |
| `-c[=force=true,keep_resources=true]` | Compact binaries by trimming unused regions and recalculating headers.                                       | `force` (bool) allows destructive trim such as removing ELF section tables. `keep_resources` preserves `.rsrc` sections unless explicitly disabled (PE only). |
| `-o[=force=true]`          | Rename sections/symbols and randomize metadata.                                                              | `force` (bool) currently behaves like a safety toggle for future advanced modes.                                                                                 |
| `-r=pattern=rx[,pattern=rules.txt][,fill=random]`   | Remove bytes that match one or more regex patterns.                                                          | Provide at least one `pattern` segment per `-r` flag. Set `pattern=/path/to/rules.txt` to load newline-separated patterns from disk (blank lines and `#` comments ignored). Optional `fill=random` switches from the default zero-fill overwrite.                                                                                    |
| `-i=name=...,file|data=...`| Insert a new (optionally encrypted) section.                                                                 | `name` optional (PE names are sanitized and truncated to 8 chars when provided). Supply exactly one of `file` or `data` (ASCII or `0x` hex) plus optional `password` (ASCII or hex).                                              |
| `-l=file|data=...`         | Append payload data as an overlay past the end of the file.                                                  | Provide `file` or `data` (ASCII or `0x` hex), not both. Optional `password` (ASCII or hex) encrypts the overlay before writing.                                   |
| `-ei=name=...|index=...`   | Extract a previously inserted section to disk.                                                               | Provide `name` or `index` (0-based). Optional `password` decrypts encrypted payloads. `destination=path` overrides the default `<input>.extracted`.                                                   |
| `-el=password=...,destination=...` | Extracts the trailing overlay into a standalone file.                                                      | `password` optional (ASCII or hex). `destination=path` overrides the default `<input>.extracted`.                                                                |
| `-p=key=value,...`         | Run the polymorphic packer over the working file.                                                            | Options share the grammar in the table below. When omitted, defaults to `compression=lzma,level=9,encryption=chacha20`.                                          |
| `-h`, `--help`, `help`     | Show CLI usage.                                                                                              | Works anywhere in the command line.                                                                                                                              |

## Operation Details

### Strip
- **Default** – removes debug info, Rich/DWARF data, Go metadata, and secondary timestamps, then repairs the relevant headers/SHT.
- **Force** – additionally purges relocations/import descriptors (PE) or loader records/SHT (ELF). Force is intended for "make it as small as possible" workflows and may break exotic binaries.

### Compact
- **Default** – trims empty/corrupt sections, recalculates SizeOfImage/headers, and rebuilds `.shstrtab` while preserving loader records.
- **Force** – allows destructive trimming (PE resources/imports, ELF segment merging and `.shstrtab` scrubbing) and overwrites slack with random data before truncation.

### Obfuscation
- **Default** – renames sections, randomizes header metadata, shuffles strings/import descriptors, fills executable padding runs with randomized NOP sequences, and now (ELF) misdirects PT_NOTE/PT_LOAD tables plus reorders `.dynsym` entries while keeping relocations in sync.
- **Force** – enables extra techniques (forged subsystem/DLL flags, fake CodeView RSDS entries, forceful import/IAT shuffling, JMP-based junk padding) and, for ELF, encrypts non-essential `.dynstr` names, clones metadata segments, and wipes `.shstrtab` before saving. Force mode still targets runnable binaries, but extremely sensitive loaders might react differently.
### Regex
- Operates on raw bytes anywhere in the binary. Inline `pattern=` values are Go regexes; pointing `pattern=` at a file loads each non-empty, non-comment line.
- Default fill uses zeroes; pass `fill=random` to scramble matches. When chained after strip/compact/obfuscate, the regex stage still honours the chosen fill mode.
- Force mode relaxes guardrails (e.g., protected ELF string tables) so risky patterns can be wiped intentionally.

### Section Insertion
- `-i` can run alone or after upstream stages (strip → compact → obfuscate → regex). Every invocation appends a new section using the format’s alignment rules so loaders keep working.
- Provide exactly one payload source: `file=path` embeds bytes from disk; `data=...` accepts ASCII or `0x`-prefixed hex. Supplying `password=` encrypts the payload before writing and marks the summary with “(encrypted)”.
- Names are optional. When provided they are sanitized automatically (PE names are truncated to 8 chars, ELF names are written into `.shstrtab`). Duplicate names are rejected so it is always clear which section was inserted.

### Overlay
- `-l` appends payload bytes after the structured binary. Like section insertion, the payload may come from `file=` or `data=` and can be encrypted with `password=`.
- Overlays are ideal for staging large configs/scripts without touching the section table. Combine with regex before/after insertion if you need to wipe staging markers.
- `-el` reads the trailing overlay and writes it to disk. When the overlay was encrypted, specify the same `password=` to decrypt it. By default the payload is saved as `<input>.extracted`, but you can provide `destination=out.bin` (or a positional output file when `-el` is the only flag).

### Section Extraction
- `-ei` works alone or after other pipeline stages, extracting a single section to disk without mutating the input binary.
- Provide either `name` (sanitized automatically; PE names are truncated to 8 chars) or `index` (0-based). When the section was inserted with `password=`, pass the same password to decrypt the payload.
- `destination=path` overrides the default `<input>.extracted`. When `destination` is omitted and `-ei` is the only operation, a positional output argument also acts as the destination to mirror the legacy grammar.

Example:

```bash
# Extract section by name
gosstrip -ei=name=.payload,password=secret sample.exe extracted.bin

# Extract the Nth section (0-based) into the default sample.exe.extracted
gosstrip -s -c -o -r=pattern=MARKER -ei=index=17,password=secret sample.exe
```

### Pack Options

When using `-p`, specify options in `key=value` format separated by commas. Quote the value on PowerShell/CMD to avoid comma parsing issues. If `-p` is provided without options, defaults are applied automatically.

- Example (PowerShell): `gosstrip.exe -p="compression=lzma,level=9,encryption=chacha20" file.exe`
- Stop-parsing alternative: `gosstrip.exe --% -p=compression=lzma,level=9,encryption=chacha20 file.exe`
- Defaults applied when omitting the option string: `compression=lzma,level=9,encryption=chacha20`

| Option        | Values                                   | Default       | Description                                   |
|---------------|------------------------------------------|---------------|-----------------------------------------------|
| `compression` | `xz`, `lzma`, `none`                     | `xz`          | Compression algorithm                         |
| `level`       | `0-9`                                    | `6`           | Compression level (0=fast, 9=best)            |
| `encryption`  | `xor`, `aes-256-gcm`, `chacha20`, `none` | `aes-256-gcm` | Encryption algorithm                          |
| `polymorphic` | `true`, `false`                          | `true`        | Enable polymorphic stub generation            |
| `junkdensity` | `0.0-1.0`                                | `0.2`         | Density of garbage code injection             |
| `padding`     | `true`, `false`                          | `true`        | Add random padding to stub                    |
| `inmemory`    | `true`, `false`                          | `false`       | Execute payload in-memory without disk writes |
| `antidebug`   | `true`, `false`                          | `false`       | Add anti-debugging checks (placeholder)       |
| `antivm`      | `true`, `false`                          | `false`       | Add anti-VM detection (placeholder)           |
| `verbose`     | `true`, `false`                          | `false`       | Detailed packing output                       |

## Examples

### Analysis

```bash
# Analyze ELF file structure
gosstrip -a /bin/ls

# Request the legacy deep analyzer and save as JSON
gosstrip -a=format=json,mode=deep /bin/bash bash-analysis.json
```

Notes:
- `-a` must be used alone and cannot be combined with other operations in the same run.
- `mode=simple` (default) prints a concise, emoji-free report suitable for logs; `mode=deep` renders the original detailed tables and also powers JSON exports if legacy data is needed.

### Stripping & Compaction

```bash
# Strip debug symbols in place
gosstrip -s binary

# Run strip + compact + obfuscation and write to a copy
gosstrip -s=force=true -c -o binary binary.hardened

# Compact aggressively
gosstrip -c=force=true binary

# Override strip fill mode to random bytes
gosstrip -s=fill=random binary

# Also drop embedded resources (icons/manifests)
gosstrip -c=force=true,keep_resources=false binary
```

Notes:
- PE: Compaction recalculates SizeOfImage/SizeOfHeaders, clears CheckSum (for unsigned binaries), and may trim trailing overlay if no Authenticode signature is present.
- ELF: With `-c=force=true`, compaction may remove the Section Header Table (SHT) to maximize size. The binary remains runnable (loaders use Program Headers), but section-based tools (objdump/readelf -S) will not work.

### Pattern Removal

```bash
# Remove multiple markers in one pass
gosstrip -r=pattern=UPX!,pattern=UPY?,pattern=v2_signature binary

# Load patterns from a file (one regex per line; blank lines / '#' comments ignored)
gosstrip -r=pattern=forensics_markers.txt binary

# Combine strip with regex (executed automatically before later operations)
gosstrip -s -r=pattern='secret_pattern' binary
```

### Section Insertion

```bash
# Insert section from file
gosstrip -i=name=.custom,file=config.bin binary

# Insert section from string literal
gosstrip -i=name=.data,data=HelloWorld binary

# Insert encrypted section (password can be ASCII or hex)
gosstrip -i=name=.secret,file=sensitive.dat,password=password123 binary

# PE section names are limited to 8 characters
gosstrip -i=name=.config,file=data.bin pe_binary.exe
```

### Overlay Operations

```bash
# Append file as overlay
gosstrip -l=file=config.json binary

# Append string as overlay
gosstrip -l=data=metadata_string binary

# Append encrypted overlay
gosstrip -l=file=sensitive.dat,password=encryption_key binary
```

### Polymorphic Packing

```bash
# Basic packing (default options)
gosstrip -p binary.exe

# Pack with explicit options and write to a new file
gosstrip -p=compression=xz,encryption=aes-256-gcm,level=9 binary.exe binary-packed.exe

# Maximum polymorphism knobs
gosstrip -p=polymorphic=true,junkdensity=0.5,padding=true binary.exe

# Favor in-memory execution
gosstrip -p=inmemory=true,encryption=chacha20 binary.exe

# Enable (placeholder) anti-analysis switches
gosstrip -p=antidebug=true,antivm=true binary.exe

# Maintain both the original and multiple packed variants
for i in {1..4}; do
    gosstrip -p=polymorphic=true sample.bin "variants/sample-$i.bin"
done
```

### Combined Operations

```bash
# Full pipeline with custom regex, section insert, overlay, and packing
gosstrip -s -c -o -r=pattern='UPX!',pattern='\\.rsrc' -i=name=.intel,file=payload.bin -l=file=overlay.bin -p=compression=lzma,inmemory=true input.exe output.exe
```

## Polymorphic Techniques

The polymorphic engine implements seven core stub generation patterns, each producing unlimited variations through randomization:

### 1. Forward XOR Decryption
Tags: stub_variant_forward_xor, forward_iteration, simple_xor, instruction_subst

Standard XOR cipher with forward iteration. Simple and fast.

```
for i := 0; i < length; i++ {
    buffer[i] = encrypted[i] ^ key[i % keylen]
}
```

### 2. Reverse XOR Decryption
Tags: stub_variant_reverse_xor, reverse_iteration, simple_xor, instruction_subst

XOR cipher with reverse iteration, different memory access pattern.

```
for i := length - 1; i >= 0; i-- {
    buffer[i] = encrypted[i] ^ key[i % keylen]
}
```

### 3. Additive Feedback Cipher
Tags: stub_variant_additive_feedback, forward_iteration, feedback_loop, additive_cipher

XOR with cumulative feedback mechanism, creates byte interdependencies.

```
feedback := byte(0)
for i := 0; i < length; i++ {
    decrypted := encrypted[i] ^ key[i % keylen] ^ feedback
    buffer[i] = decrypted
    feedback = (feedback + decrypted) & 0xFF
}
```

### 4. XOR with Rotation
Tags: stub_variant_xor_rotate, forward_iteration, bit_rotation, xor

Combines XOR with bit rotation for additional complexity.

```
for i := 0; i < length; i++ {
    xored := encrypted[i] ^ key[i % keylen]
    rotated := (xored << 3) | (xored >> 5)
    buffer[i] = rotated
}
```

### 5. Multi-Pass Decryption
Tags: stub_variant_multi_pass, multi_pass_decrypt, xor, additive

Three-stage decryption with different keys per pass.

```
// Pass 1: XOR
for i := 0; i < length; i++ {
    buffer[i] = encrypted[i] ^ key1[i % keylen]
}
// Pass 2: Subtraction
for i := 0; i < length; i++ {
    buffer[i] -= key2[i % keylen]
}
// Pass 3: XOR final
for i := 0; i < length; i++ {
    buffer[i] ^= key3[i % keylen]
}
```

### 6. Block Cipher with Randomized Operations
Tags: stub_variant_block_cipher_random, block_cipher, random_ops, multi_operation

Processes data in 16-byte blocks with random cipher operations selected per build.

Available operations:
- XOR: `result = data ^ key`
- ADD: `result = (data + key) & 0xFF`
- SUB: `result = (data - key) & 0xFF`
- ROL: `result = (data << 3) | (data >> 5)`
- ROR: `result = (data >> 3) | (data << 5)`
- NOT+XOR: `result = (^data) ^ key`

Each block randomly uses different operation combinations, creating millions of unique cipher sequences.

### 7. Control Flow Obfuscated
Tags: stub_variant_control_flow_obf, control_flow_obf, switch_based, complex_flow

Combines decryption with randomized control flow patterns.

Features:
- Random loop styles (for/while/do-while)
- Random conditional styles (if/switch/ternary)
- Random storage variants (array/slice/pointer/direct)
- Switch-based control flow
- Variable increment patterns

### Global tags (reported where applicable)

- padding_entropy
- unique_hash
- elf_pad_randomization (ELF only)

### Variable Name Randomization

All stubs use randomized variable names from a pool of 72 combinations:

**Base names**: data, buffer, temp, val, ptr, idx, cnt, len, key, src, dst, result  
**Suffixes**: _arr, _buf, _tmp, _var, _ptr, _val

Example variations:
```
// Build 1          // Build 2          // Build 3
data_buf := ...     buffer_arr := ...   src_tmp := ...
temp_var := ...     val_ptr := ...      dst_val := ...
```

### Garbage Code Injection

Strategic insertion of 2-5 dead code patterns per stub:

1. Impossible conditionals: `if 1 == 0 { _ = rand.Intn(100) }`
2. Zero-effect arithmetic: `_ = (x * 0) + (y - y)`
3. Unused declarations: `_ = [16]byte{}`
4. Commented blocks: `/* dead code */`
5. No-op functions: `func noop() {}; noop()`

## Technical Specifications

### Polymorphic Capabilities

**Unique Combinations per Build**:
- 7 stub variant patterns
- 6 block cipher operations (random per block)
- 72 variable name combinations per identifier
- 3 control flow styles
- 5 garbage code patterns

**Result**: Effectively infinite unique variants. No two builds produce identical binaries.

### Performance Metrics

**Size Overhead**:
- Stub size: 8-12 KB
- Overhead: <0.2% for binaries >1 MB
- Example: 10 MB binary → 10.012 MB packed

**Runtime Overhead**:
- Decryption time: 5-10 ms
- Zero impact after unpacking
- Negligible startup time increase

**Build Time**:
- Stub generation: <50 ms
- Encryption: <100 ms
- Total pack time: <500 ms

### Security Properties

**Uniqueness Guarantee**:
- 100% unique SHA256 hashes (tested with 50+ builds)
- Zero hash collisions
- Statistical uniform distribution across all 7 variants

**Execution Integrity**:
- 100% execution success rate
- Bit-identical unpacked payload
- Preserved binary functionality

**Anti-Analysis Features**:
- No static stub signatures
- Randomized control flow patterns
- Variable obfuscation
- Dead code insertion
- Block-level operation randomization

## In-Memory Execution

The `inmemory=true` option enables fileless execution, eliminating disk traces during payload execution.

### Linux Implementation: memfd_create

**Technique**: Anonymous memory file descriptor execution

**How it works**:
1. Creates anonymous file descriptor in memory using `memfd_create` syscall (319)
2. Writes decrypted payload to memfd (no disk I/O)
3. Executes via `/proc/self/fd/N` path
4. Automatic fallback to temporary file if memfd_create unavailable

**Key Features**:
- Zero disk writes during execution
- No traces in `/tmp` or any filesystem
- Works even with `/tmp` mounted as noexec
- Bypasses file permission checks (fexecve approach)
- Kernel 3.17+ required (most modern Linux distributions)

**Security Considerations**:
- ✅ No filesystem artifacts
- ✅ Memory-only execution path
- ✅ Works in restricted environments
- ⚠️ EDR systems may monitor `memfd_create` syscall
- ⚠️ SELinux policies might block memfd execution
- ⚠️ Memory scanning can still detect decrypted payload

**Implementation Details**:
```go
// syscall 319: memfd_create("exec", MFD_CLOEXEC)
fd, _, errno := syscall.Syscall(319, uintptr(unsafe.Pointer(&name[0])), 1, 0)

// Write payload in chunks (handles partial writes)
for totalWritten < len(payload) {
    n, err := syscall.Write(int(fd), payload[totalWritten:])
    totalWritten += n
}

// Execute via /proc/self/fd/N
fdPath := "/proc/self/fd/" + itoa(int(fd))
syscall.Exec(fdPath, os.Args, os.Environ())
```

**Performance**:
- Overhead: ~5ms for memfd creation + write
- Memory: 1x payload size in RAM
- Zero I/O wait time

**Compatibility**:
- ✅ Linux Kernel >= 3.17
- ✅ x86_64, ARM64 architectures
- ✅ All major distributions (Ubuntu 16.04+, Debian 9+, CentOS 7+, Arch, etc.)
- ⚠️ Containers: requires /proc filesystem access
- ⚠️ SELinux: may require policy adjustments

### Windows Implementation: Process Hollowing

**Technique**: RunPE / Process Replacement (PEB-aware)

**How it works**:
1. Creates suspended process with CREATE_SUSPENDED flag
2. Reads thread context to access PEB (Process Environment Block)
3. Extracts actual ImageBase from PEB+16 (not from PE header)
4. Unmaps original image using NtUnmapViewOfSection
5. Parses PE headers (DOS header, PE signature, Optional Header)
6. Allocates memory at preferred ImageBase with VirtualAllocEx
7. Writes PE headers and all sections to target memory
8. Updates PEB with new ImageBase address (critical for ASLR)
9. Updates thread context RCX register to entry point
10. Resumes thread execution

**Key Features**:
- Zero disk writes during execution
- Payload executes from legitimate process context
- **PEB-based ImageBase detection** (correct for ASLR)
- **PEB update after hollowing** (prevents crashes)
- **Full error checking** with automatic fallback
- Section-by-section memory writing with validation
- Full context manipulation (1232-byte CONTEXT structure)

**Security Considerations**:
- ✅ No filesystem artifacts
- ✅ Executes from legitimate process
- ✅ Bypasses signature-based AV
- ✅ Handles ASLR correctly via PEB
- ⚠️ Behavioral AV detects CreateProcess + WriteProcessMemory pattern
- ⚠️ Windows Defender with HVCI may block
- ⚠️ Memory scanning can detect payload

**Implementation Details**:
```go
// 1. Create suspended process
CreateProcessW(exePath, NULL, NULL, NULL, FALSE, 
               CREATE_SUSPENDED, NULL, NULL, &si, &pi)

// 2. Get context and access PEB
ctx := make([]byte, 1232)  // Full CONTEXT structure
binary.LittleEndian.PutUint32(ctx[48:], 0x00100002)  // CONTEXT_INTEGER
GetThreadContext(pi.Thread, &ctx)
Rdx := binary.LittleEndian.Uint64(ctx[136:])  // PEB pointer

// 3. Read actual ImageBase from PEB+16
ReadProcessMemory(pi.Process, Rdx+16, &baseAddr, 8, &read)

// 4. Unmap original image at correct address
NtUnmapViewOfSection(pi.Process, baseAddr)

// 5. Parse PE and allocate
peOffset := binary.LittleEndian.Uint32(payload[0x3C:])
imageBase := binary.LittleEndian.Uint64(payload[optHeaderOffset+24:])
sizeOfImage := binary.LittleEndian.Uint32(payload[optHeaderOffset+56:])
entryPoint := binary.LittleEndian.Uint32(payload[optHeaderOffset+16:])

newBase := VirtualAllocEx(pi.Process, imageBase, sizeOfImage, 
                          MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

// 6. Write PE with validation
written := 0
WriteProcessMemory(pi.Process, newBase, headers, size, &written)
if written != size { fallback() }

// 7. Update PEB with new ImageBase (CRITICAL)
newBaseBytes := uint64ToBytes(newBase)
WriteProcessMemory(pi.Process, Rdx+16, newBaseBytes, 8, &written)

// 8. Update context entry point (offset 128 = RCX for x64)
binary.LittleEndian.PutUint64(ctx[128:], newBase + entryPoint)
SetThreadContext(pi.Thread, &ctx)

// 9. Resume
ResumeThread(pi.Thread)
```

**Performance**:
- Overhead: ~50ms for process creation + hollowing
- Memory: 2x payload size (host + hollowed process)
- Zero I/O wait time

**Improvements vs Standard Implementation**:
- ✅ PEB-aware ImageBase detection (handles ASLR)
- ✅ PEB update prevents crashes
- ✅ Full error checking on all syscalls
- ✅ Automatic fallback to temp file
- ✅ Proper CONTEXT structure (1232 bytes)
- ✅ Validated based on [fistfulofhummus/Process-Hollowing-in-Go](https://github.com/fistfulofhummus/Process-Hollowing-in-Go)

**Compatibility**:
- ✅ Windows 7, 8, 10, 11
- ✅ x86 and x64 architectures
- ⚠️ Windows 10+ with HVCI: may fail
- ⚠️ Modern EDR: high detection rate

**Limitations**:
- Relocations not currently handled (assumes correct ImageBase)
- Import Address Table (IAT) not reconstructed
- Best for self-contained executables with minimal imports

### Fallback Mechanism

Both implementations include automatic fallback to temporary file execution:

**Linux Fallback Triggers**:
- `memfd_create` syscall fails (kernel < 3.17)
- Memory write fails
- `/proc` filesystem not mounted
- Any syscall error during setup

**Windows Fallback Triggers**:
- PE header parsing fails
- CreateProcess fails
- NtUnmapViewOfSection fails
- VirtualAllocEx fails
- Any hollowing step error

**Fallback Behavior**:
```go
func executeFromTemp(payload []byte) {
    tmp, _ := os.CreateTemp("", ".tmp-*")
    tmp.Write(payload)
    tmp.Chmod(0755)
    tmp.Close()
    
    cmd := exec.Command(tmp.Name(), os.Args[1:]...)
    cmd.Run()
    
    os.Remove(tmp.Name())  // Clean up after execution
}
```

### Usage Examples

```bash
# Linux: memfd_create execution
./gosstrip -p=inmemory=true,encryption=aes-256-gcm binary
./binary.packed  # Runs entirely in memory

# Windows: Process Hollowing
gosstrip.exe -p=inmemory=true,encryption=chacha20 binary.exe
binary.exe.packed  # Executes via process hollowing

# Combined with polymorphism for maximum evasion
./gosstrip -p=polymorphic=true,inmemory=true,junkdensity=0.5 binary

# Full stealth: polymorphic + in-memory + anti-analysis
./gosstrip -p=polymorphic=true,inmemory=true,antidebug=true,antivm=true binary
```

### Verification

```bash
# Linux: Verify no temp files created
./binary.packed &
PID=$!
ls -la /tmp | grep -i tmp  # Should be empty
lsof -p $PID | grep -E '(tmp|deleted)'  # Check for deleted temp files
cat /proc/$PID/maps | grep memfd  # Should show memfd mapping

# Windows: Verify process hollowing (requires Process Explorer)
# 1. Run binary.packed
# 2. Open Process Explorer
# 3. Check process memory sections - should differ from disk image
# 4. Verify entry point is custom (not default)
```

### Best Practices

**For Maximum Stealth**:
1. Combine `inmemory=true` with `polymorphic=true`
2. Use strong encryption (aes-256-gcm or chacha20)
3. Enable anti-analysis features (`antidebug=true`, `antivm=true`)
4. Test in target environment (EDR/AV detection rates vary)

**For Production Use**:
1. Always test fallback behavior
2. Monitor for detection (EDR alerts on memfd_create/CreateProcess)
3. Consider environment compatibility (kernel version, Windows version)
4. Use appropriate encryption for compliance requirements

**Performance Considerations**:
- In-memory execution adds <50ms overhead (Linux: ~5ms, Windows: ~50ms)
- Memory usage: 1-2x payload size during execution
- No disk I/O - faster than temp file approach
- CPU overhead: minimal (encryption/decompression only)

**Anti-Analysis Features**:
- No static signatures (polymorphic stub)
- No disk artifacts (in-memory execution)
- Variable control flow (randomized patterns)
- Dead code injection (hinders static analysis)
- Block cipher randomization (unique per build)

## Testing

### Polymorphism Test Suite

Run the comprehensive test suite to validate all polymorphic capabilities:

```bash
# Quick test (10 builds, ~10 seconds)
./test_polymorphism.sh quick

# Full test (50 builds with analysis, ~60 seconds)
./test_polymorphism.sh full
```

### Test Modules

1. **Hash Uniqueness & Execution**: Validates 100% unique hashes and execution success
2. **Baseline Comparison**: Compares polymorphic vs non-polymorphic builds
3. **Performance Metrics**: Measures size overhead and build times

### Manual Testing

```bash
# Build test binary
cd testfiles
go build -o test_binary simple_go.go
cd ..

# Pack and verify
gosstrip -p=polymorphic=true testfiles/test_binary
sha256sum testfiles/test_binary.packed
./testfiles/test_binary.packed

# Generate multiple variants and compare
for i in {1..5}; do
    gosstrip -p testfiles/test_binary
    sha256sum testfiles/test_binary.packed | tee hash_$i.txt
    ./testfiles/test_binary.packed
done

# Verify all hashes are unique
cat hash_*.txt | sort | uniq | wc -l  # Should equal 5
```

### CLI Matrix Regression Script

Use the bundled matrix runner to capture canonical CLI flows (analyze → obfuscate and analyze → strip → compact → obfuscate) for both PE and ELF targets in default and force modes. The script builds fresh fixtures with `x86_64-w64-mingw32-gcc` and either local `gcc` or WSL’s toolchain, then stores every command transcript under timestamped folders for later review.

```bash
bash test/cli_matrix.sh
# => logs under test/logs/cli_matrix_YYYYMMDD_HHMMSS/
```

Inspect the resulting logs to compare analyzer output before/after each stage or to archive regression evidence for future troubleshooting.

### Manual Regression Flows

When validating changes outside of the automated suites, build `gosstrip`, compile the fixtures under `testfiles/`, and copy the binaries to a scratch area (e.g., `temp-manual-pipeline/runs/$ts/work/…`). Every manual run MUST:

- execute `analyze(mode=deep)` before and after the operations being tested, and
- store each command transcript (stdout + stderr) so the resulting logs can be inspected. Keep them under `temp-manual-pipeline/runs/<timestamp>/logs_py/` (or similar) alongside the fixtures you used, and review the analyzer summaries afterward to ensure no new warnings slipped in.

Run the sequences below for both PE and ELF targets in default **and** force mode, substituting the appropriate CLI options:

1. **Single-feature validation**
   ```
   analyze(mode=deep) → <feature flag + all relevant options> → analyze(mode=deep)
   ```
   (Example: `-r=pattern=ANALYZE_REGEX_MARKER`, `-i=name=.x,data=PAYLOAD`, etc.)

2. **Pipeline – short version**
   ```
   analyze(mode=deep)
   → strip(fill=zero/random, force=false/true)
   → compact(force=false/true)
   → obfuscate(force=false/true)
   → analyze(mode=deep)
   ```

3. **Pipeline – full version**
   ```
   analyze(mode=deep)
   → strip(fill=zero/random, force=false/true)
   → compact(force=false/true)
   → obfuscate(force=false/true)
   → regex(pattern=<file or inline pattern list>)
   → insertion(all options)
   → overlay(all options)
   → analyze(mode=deep)
   ```

4. **Pack-only regression**
   ```
   analyze(mode=deep) → pack(all options) → analyze(mode=deep)
   ```

Tips:

- Use inline markers (e.g., append `ANALYZE_REGEX_MARKER` to the test binary) when validating regex-only flows.
- Pattern files accept one regex per line; blank lines and `# comments` are ignored.
- When running force-mode pipelines, set `force=true` on strip/compact/obfuscate exactly as the user workflows do, then compare the final deep analyzer output with previous runs to ensure new warnings/errors are understood.

## Architecture

### Execution Flow

**Packing Process**:
1. Parse input binary (ELF/PE)
2. Compress payload (XZ/LZMA/none)
3. Encrypt payload with random key
4. Select random stub variant (1 of 7)
5. Apply block cipher randomization (6 operations)
6. Randomize variable names (72 combinations)
7. Inject garbage code (2-5 insertions)
8. Generate Go stub source code and inject a random stub variant (anchored via init())
9. Compile stub and append [Encrypted Payload]Metadata Size (8B LE) to the stub trailer
10. Write final packed binary

**Unpacking Process (Runtime)**:

*Standard Execution (inmemory=false)*:
1. Execute packed binary
2. Stub decrypts embedded payload in memory
3. Write decrypted payload to temporary file
4. Execute temporary file
5. Remove temporary file after execution
6. Original program runs normally

*In-Memory Execution (inmemory=true)*:

**Linux (memfd_create)**:
1. Execute packed binary
2. Stub decrypts embedded payload in memory
3. Create anonymous memory file descriptor via `memfd_create` syscall (319)
4. Write decrypted payload to memory fd (no disk I/O)
5. Execute via `/proc/self/fd/N` path using `syscall.Exec`
6. Zero disk traces - payload never touches filesystem

**Windows (Process Hollowing)**:
1. Execute packed binary
2. Stub decrypts embedded payload in memory
3. Parse PE headers (DOS, PE signature, Optional Header)
4. Create suspended target process (CREATE_SUSPENDED)
5. Unmap original image with NtUnmapViewOfSection
6. Allocate memory in target process (VirtualAllocEx)
7. Write PE headers and sections to target memory
8. Update thread context (RIP/EIP → entry point)
9. Resume thread execution
10. Zero disk traces - payload executes from hollowed process
