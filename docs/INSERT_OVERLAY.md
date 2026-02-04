# SECTION INSERTION & OVERLAY OPERATIONS

The `-i` (section insertion) and `-l` (overlay) stages let users embed payloads inside a binary. They are often combined with obfuscation and packing. This doc explains the grammar, encryption support, and PE/ELF specifics.

## 1. CLI Grammar

### Section Insertion (`-i`)

```
-i=name=.secret,data=plain_text[,password=passphrase]
-i=name=.key,file=payload.bin[,password=hex:0011aa...]
```

- `name` is required for `-i`. PE section names are sanitized to fit COFF limits (8 bytes).
- Provide exactly one of `data` (inline string; prefix with `hex:` to feed raw hex) or `file` (path on disk).
- Optional `password` encrypts the payload using AES-256-GCM. If the password looks like hex, it is decoded and used as the key input.

Insertion creates a new section header with `IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA` (PE) or `SHT_PROGBITS` + `SHF_ALLOC` (ELF). There is no force flag for insert/overlay.

### Overlay (`-l`)

```
-l=data=OVERLAY_BYTES[,password=secret]
-l=file=payload.bin[,password=secret]
```

- Appends the payload past the logical end of the file. Authenticode signatures will be invalidated unless you re-sign the binary later.
- Encryption works the same way as insertion.

## 2. PE Handling

- New sections are appended after existing sections and aligned to `FileAlignment` and `SectionAlignment`.
- Section tables and `NumberOfSections` are updated. Compact/obfuscate respect inserted sections and will not remove user data by default.
- Overlay replaces any existing overlay, then appends the new payload and updates overlay metadata (offset/size).

## 3. ELF Handling

- Inserts a new `SHT_PROGBITS` entry and rebuilds the section headers. If the ELF has no section headers, insertion is rejected.
- For overlays we truncate sections at the logical file end, rebuild section headers, then append the payload.
- Alignment is 16 bytes for the new section data.

## 4. Encryption Workflow

1. Derive a key from `password` (SHA-256 of bytes; hex strings are decoded first).
2. Encrypt payload with AES-256-GCM; IV + tag are stored alongside ciphertext.

Without a password, payloads are stored verbatim.

## 5. Testing

- CLI integration tests verify insertion/overlay by checking the data appears in the modified binary.
- Developers can run `test/cli_matrix.sh` to capture analyze output and ensure inserted sections are recognized.
