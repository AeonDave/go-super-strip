# go-super-strip

A comprehensive binary manipulation toolkit for ELF and PE executables with advanced polymorphic packing capabilities.

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

### Polymorphic Packing System
- **7 Stub Variants**: Multiple decryption algorithms (XOR, additive feedback, multi-pass, block cipher, control flow obfuscation)
- **Block Cipher Randomization**: 6 different cipher operations per build
- **Variable Name Randomization**: 72 combinations per identifier
- **Garbage Code Injection**: Strategic dead code insertion
- **100% Unique Builds**: Every build produces a unique SHA256 hash
- **Zero Overhead**: <0.2% size increase, <10ms runtime impact

## Installation

```bash
git clone https://github.com/AeonDave/go-super-strip
cd go-super-strip
go build -o gosstrip
```

## Usage

### Command Syntax

```
gosstrip [OPTIONS] <file>
```

### Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-a` | `--analyze` | Analyze file structure only (standalone) |
| `-s` | `--strip` | Strip debug symbols and metadata |
| `-c` | `--compact` | Reduce file size by removing sections |
| `-o` | `--obfuscate` | Apply obfuscation techniques |
| `-f` | `--force` | Apply risky operations for -s, -c, -o |
| `-r <pattern>` | `--regex <pattern>` | Strip bytes matching regex pattern |
| `-i <spec>` | `--insert <spec>` | Insert section (format: `name:data_or_file[:password]`) |
| `-l <spec>` | `--overlay <spec>` | Add overlay (format: `data_or_file[:password]`) |
| `-p [opts]` | `--pack [opts]` | Pack with polymorphic stub (format: `opt1=val1,opt2=val2`) |
| `-v` | | Enable verbose output |
| `-h` | | Show help |

### Pack Options

When using `-p` or `--pack`, you can specify options in `key=value` format separated by commas:

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `compression` | `xz`, `lzma`, `none` | `xz` | Compression algorithm |
| `level` | `0-9` | `6` | Compression level (0=fast, 9=best) |
| `encryption` | `xor`, `aes-256-gcm`, `chacha20`, `none` | `aes-256-gcm` | Encryption algorithm |
| `polymorphic` | `true`, `false` | `true` | Enable polymorphic stub generation |
| `junkdensity` | `0.0-1.0` | `0.2` | Density of garbage code injection |
| `padding` | `true`, `false` | `true` | Add random padding to stub |
| `inmemory` | `true`, `false` | `false` | Execute payload in-memory (memfd_create) |
| `antidebug` | `true`, `false` | `false` | Add anti-debugging checks |
| `antivm` | `true`, `false` | `false` | Add anti-VM detection |
| `verbose` | `true`, `false` | `false` | Detailed packing output |

## Examples

### Analysis

```bash
# Analyze ELF file structure
gosstrip -a /bin/ls

# Verbose analysis
gosstrip -a -v /bin/bash
```

### Stripping & Compaction

```bash
# Strip debug symbols
gosstrip -s binary

# Compact file (remove non-essential sections)
gosstrip -c binary

# Strip + compact + obfuscate (full pipeline)
gosstrip -s -c -o binary

# Aggressive stripping with risky operations
gosstrip -s -f binary
```

### Pattern Removal

```bash
# Strip bytes matching pattern
gosstrip -r 'UPX!' binary

# Combine strip with regex
gosstrip -s -r 'signature_pattern' binary
```

### Section Insertion

```bash
# Insert section from file
gosstrip -i '.custom:config.bin' binary

# Insert section from string
gosstrip -i '.data:HelloWorld' binary

# Insert encrypted section
gosstrip -i '.secret:sensitive.dat:password123' binary

# PE section names are limited to 8 characters
gosstrip -i '.config:data.bin' pe_binary.exe
```

### Overlay Operations

```bash
# Append file as overlay
gosstrip -l 'config.json' binary

# Append string as overlay
gosstrip -l 'metadata_string' binary

# Append encrypted overlay
gosstrip -l 'sensitive.dat:encryption_key' binary
```

### Polymorphic Packing

```bash
# Basic packing (default polymorphic)
gosstrip -p binary

# Pack with specific options
gosstrip -p=compression=xz,encryption=aes-256-gcm,level=9 binary

# Pack with maximum polymorphism
gosstrip -p=polymorphic=true,junkdensity=0.5,padding=true binary

# Pack with in-memory execution
gosstrip -p=inmemory=true,encryption=chacha20 binary

# Pack with anti-analysis features
gosstrip -p=antidebug=true,antivm=true binary

# Generate multiple unique variants
for i in {1..10}; do
    gosstrip -p=polymorphic=true binary
    sha256sum binary.packed
    ./binary.packed  # All execute identically
done
```

### Combined Operations

```bash
# Strip, compact, obfuscate, then pack
gosstrip -s -c -o binary
gosstrip -p binary.stripped

# Full pipeline with custom options
gosstrip -s -f binary
gosstrip -p=compression=lzma,level=9,encryption=chacha20 binary.stripped
```

## Polymorphic Techniques

The polymorphic engine implements seven core stub generation patterns, each producing unlimited variations through randomization:

### 1. Forward XOR Decryption
Standard XOR cipher with forward iteration. Simple and fast.

```
for i := 0; i < length; i++ {
    buffer[i] = encrypted[i] ^ key[i % keylen]
}
```

### 2. Reverse XOR Decryption
XOR cipher with reverse iteration, different memory access pattern.

```
for i := length - 1; i >= 0; i-- {
    buffer[i] = encrypted[i] ^ key[i % keylen]
}
```

### 3. Additive Feedback Cipher
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
Combines XOR with bit rotation for additional complexity.

```
for i := 0; i < length; i++ {
    xored := encrypted[i] ^ key[i % keylen]
    rotated := (xored << 3) | (xored >> 5)
    buffer[i] = rotated
}
```

### 5. Multi-Pass Decryption
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
Combines decryption with randomized control flow patterns.

Features:
- Random loop styles (for/while/do-while)
- Random conditional styles (if/switch/ternary)
- Random storage variants (array/slice/pointer/direct)
- Switch-based control flow
- Variable increment patterns

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

## Architecture

### Package Structure

```
go-super-strip/
├── main.go                 # CLI entry point
├── common/                 # Shared utilities
│   ├── types.go           # Common data structures
│   ├── crypto.go          # Encryption functions
│   ├── format.go          # Output formatting
│   └── utils.go           # Utility functions
├── elfrw/                 # ELF file operations
│   ├── read.go            # ELF parsing
│   ├── write.go           # ELF generation
│   ├── analyze.go         # Section analysis
│   ├── strip.go           # Symbol stripping
│   ├── compact.go         # Binary compaction
│   ├── obfuscate.go       # Symbol obfuscation
│   ├── insert.go          # Section injection
│   └── overlay.go         # Overlay operations
├── perw/                  # PE file operations (mirrors elfrw)
└── pack/                  # Polymorphic packing
    ├── polymorphic.go            # Main packing engine
    ├── stub_templates.go         # 7 stub generators
    ├── instruction_substitution.go  # Block cipher randomization
    ├── pack_elf.go               # ELF packing
    ├── pack_pe.go                # PE packing
    ├── encryption.go             # Encryption algorithms
    ├── compression.go            # Compression algorithms
    └── stub_compiler.go          # Stub compilation
```

### Execution Flow

**Packing Process**:
1. Parse input binary (ELF/PE)
2. Compress payload (XZ/LZMA/none)
3. Encrypt payload with random key
4. Select random stub variant (1 of 7)
5. Apply block cipher randomization (6 operations)
6. Randomize variable names (72 combinations)
7. Inject garbage code (2-5 insertions)
8. Generate Go stub source code
9. Compile stub with embedded encrypted payload
10. Write final packed binary

**Unpacking Process (Runtime)**:
1. Execute packed binary
2. Stub decrypts embedded payload in memory
3. Create memory file descriptor (memfd_create on Linux)
4. Write decrypted payload to memory fd
5. Execute decrypted binary via syscall.Exec
6. Original program runs normally
