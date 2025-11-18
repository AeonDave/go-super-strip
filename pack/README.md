# Pack Module

The `pack` package provides executable packing with compression, encryption, and a simple polymorphic stub for ELF and PE binaries.

Note on current status:
- Compression supports xz, lzma, or none.
- Encryption supports xor, aes-256-gcm, chacha20, or none.
- Advanced multi-variant polymorphism is integrated: a random stub variant is injected into the compiled stub at build time and anchored via init(), producing per-build unique binaries. Light post-compile tweaks (e.g., ELF EI_PAD entropy) are also applied where safe.
- In-memory execution is available (memfd_create on Linux, process hollowing on Windows) with automatic fallbacks to temporary files.

## File Structure

### Core Files

- `pack.go`: CLI-facing entry point to perform packing via Pack(filePath, optionsString)
- `config.go`: Options parsing, defaults, and validation
- `common.go`: Shared types (PackResult, PayloadMetadata, etc.)
- `helpers.go`: Utility helpers (hashes, formatting)

### Compression and Encryption

- `compression.go`: Compression algorithms (XZ, LZMA)
- `encryption.go`: Encryption algorithms (XOR, AES-256-GCM, ChaCha20-Poly1305)

### Per-Format Packers

- `pack_elf.go`: ELF packer (Linux)
- `pack_pe.go`: PE packer (Windows)

### Stub Templates

- `stub_template_elf.go`: Go stub for ELF (self-extracting)
- `stub_template_pe.go`: Go stub for PE (self-extracting)
- `stub_compiler.go`: Stub compilation and metadata embedding

### Polymorphism

- `polymorphic.go`: Engine that aggregates technique tags and applies safe post-compile tweaks (e.g., ELF EI_PAD entropy)
- `stub_templates.go`: Advanced multi-variant stub generator (integrated into compiled stubs)
- `instruction_substitution.go`: Helpers used by the variant generator

### Tests

- `config_test.go`: Options parsing and validation tests
- `pack_test.go`: Basic packing tests (compression/encryption paths)

## Usage

You can call the packer from the CLI via gosstrip -p, or programmatically.

### CLI (recommended)

- Options are specified as: key=value pairs separated by commas.
- Full option names are preferred; some shorthands are also accepted.

Supported options and defaults:
- compression=xz|lzma|none (default: xz)
- level=0-9 (default: 6)
- encryption=xor|aes-256-gcm|chacha20|none (default: aes-256-gcm)
- polymorphic=true|false (default: true)  [alias: poly]
- junkdensity=0.0-1.0 (default: 0.2)
- padding=true|false (default: true)
- inmemory=off|auto|memfd|process_hollowing (default: off; memfd is Linux-only, process_hollowing is Windows-only)  [alias: inmem]
- verbose=true|false (default: false)  [alias: v]

Examples:
- gosstrip -p target_binary
- gosstrip -p="compression=lzma,level=9,encryption=chacha20" target_binary
- gosstrip -p=polymorphic=true,junkdensity=0.5 target_binary
- gosstrip -p=inmemory=auto target_binary

### Programmatic

Simple example using the high-level Pack function:

```go
package main

import (
    "log"
    "gosstrip/pack"
)

func main() {
    // Options string (same format as CLI)
    opts := "compression=xz,level=6,encryption=aes-256-gcm,polymorphic=true"

    if err := pack.Pack("input_binary", opts); err != nil {
        log.Fatalf("pack failed: %v", err)
    }
}
```

If you need more control, you can parse/validate options first and then call Pack:

```go
cfg, err := pack.ParseOptions("comp=lzma,encr=chacha20,level=9,poly=true")
if err != nil { /* handle */ }
if err := cfg.Validate(); err != nil { /* handle */ }
// Then run pack via the CLI entry point:
if err := pack.Pack("input_binary", "comp=lzma,encr=chacha20,level=9,poly=true"); err != nil { /* handle */ }
```

## Architecture

### Packing Flow

1. Read original file
2. Optional random padding
3. Compress payload (xz/lzma/none)
4. Encrypt payload (xor/aes-256-gcm/chacha20/none)
5. Create metadata block (algorithms, sizes, keys, nonce)
6. Compile a self-extracting Go stub
7. Apply light polymorphism (e.g., header/padding randomization)
8. Append payload + metadata to stub
9. Write final packed file

### Packed File Layout

```
[ Stub Binary ]
[ Encrypted Payload ]
[ Metadata (algorithms, keys, nonce, sizes) ]
[ Metadata Size (8 bytes, little-endian) ]
```

The stub reads the trailing 8 bytes to get the metadata size, then reads metadata and payload from the end of the file.

### Self-Extracting Stub

At runtime the stub:
1. Locates and parses its embedded metadata and payload
2. Decrypts the payload using the embedded key/nonce
3. Decompresses the payload
4. Executes the original payload
   - Linux: tries memfd_create-based in-memory execution; falls back to temp file
   - Windows: uses a simplified process hollowing routine; falls back to temp file

## Testing

Run tests for the pack module:

```bash
go test ./pack -v
```

## Implementation Notes

- Polymorphism now includes an advanced multi-variant stub generator injected at build time (anchored via init()), plus safe post-compile tweaks where applicable (e.g., ELF EI_PAD entropy). The packer prints the exact technique tags used in the output details.
- In-memory execution paths are implemented and include automatic fallbacks (Linux: memfd_create; Windows: process hollowing).

## Dependencies

- github.com/ulikunitz/xz — XZ/LZMA compression
- golang.org/x/crypto/chacha20poly1305 — ChaCha20-Poly1305 encryption


## Polymorphic technique tags

When polymorphic=true, the packer prints the exact techniques it applied in the result details. These are the tags you may see:

- Variant tags (one per build):
  - stub_variant_forward_xor
  - stub_variant_reverse_xor
  - stub_variant_additive_feedback
  - stub_variant_xor_rotate
  - stub_variant_multi_pass
  - stub_variant_block_cipher_random
  - stub_variant_control_flow_obf

- Feature tags (depending on the selected variant):
  - forward_iteration, reverse_iteration, feedback_loop, additive_cipher, bit_rotation,
    multi_pass_decrypt, block_cipher, random_ops, multi_operation, control_flow_obf,
    switch_based, complex_flow, instruction_subst

- Global tags:
  - padding_entropy
  - unique_hash
  - elf_pad_randomization (ELF only)

Example output excerpt:

  Polymorphic techniques: [stub_variant_multi_pass multi_pass_decrypt xor additive padding_entropy unique_hash]
