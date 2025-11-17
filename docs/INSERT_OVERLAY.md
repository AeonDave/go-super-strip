# SECTION INSERTION & OVERLAY OPERATIONS

The `-i` (sector insertion) and `-l` (overlay/loader) stages let users embed payloads inside a binary. They are often combined with obfuscation and packing. This doc explains the grammar, encryption support, and PE/ELF specifics.

## 1. CLI Grammar

### Section Insertion (`-i`)

```
-i=name=.secret,data=plain_text[,password=passphrase]
-i=name=.key,file=payload.bin[,password=hex:0011aa...]
```

- `name` (required) must be <= 8 bytes for PE (due to COFF limits). ELF allows longer strings but the tool enforces the same limit for consistency.
- Provide exactly one of `data` (inline string; prefix with `hex:` to feed raw hex) or `file` (path on disk).
- Optional `password` encrypts the payload using AES-256-GCM with a random IV. Strings are UTF-8; `hex:` toggles raw bytes.

Insertion always creates a new section header with `IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA` (PE) or `SHT_PROGBITS` and read-only flags (ELF). Force mode allows executable sections.

### Overlay (`-l`)

```
-l=data=OVERLAY_BYTES[,password=secret]
-l=file=payload.bin[,password=secret]
```

- Appends the payload past the logical end of the file. Authenticode signatures will be invalidated unless you re-sign the binary later.
- Encryption works the same way as insertion.

## 2. PE Handling

- New sections are appended after existing headers, aligned to `FileAlignment` and `SectionAlignment`.
- Section tables and `NumberOfSections` are updated. Compact/obfuscate respect inserted sections by default; force obfuscation may rename them but never removes user data.
- Overlay metadata records the offset, length, and encryption parameters so analysis can report them.

## 3. ELF Handling

- Inserts a new `SHT_PROGBITS` entry plus, if required, a PT_NOTE segment describing the payload for loaders.
- For overlays we extend the file beyond the last LOAD segment and optionally add a PT_NOTE referencing the data.
- Alignment respects the maximum of page size and existing `sh_addralign`.

## 4. Encryption Workflow

1. Derive a key from `password` (PBKDF2-HMAC-SHA256).
2. Encrypt payload with AES-256-GCM; store IV + auth tag alongside ciphertext.
3. Analyzer understands this format and labels the sections as “Encrypted (AES-256-GCM)”.

Without a password, payloads are stored verbatim.

## 5. Force Mode

- Force allows executable flags on inserted PE sections, and marks ELF sections as alloc+exec.
- Overlay force mode can also append randomized padding and write metadata to confuse static tools.

## 6. Testing

- CLI integration tests verify insertion/overlay by checking the data appears in the modified binary.
- Developers can run `tests/cli_matrix.sh` to capture analyze output and ensure inserted sections are recognized.
