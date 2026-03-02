# SECTION INSERTION & OVERLAY OPERATIONS

The `-i` (section insertion) and `-l` (overlay) stages let users embed payloads inside a binary.

## 1. CLI Grammar

### Section Insertion (`-i`)

```
-i=name=.secret,data=hello[,password=passphrase]
-i=name=.secret,data=0x68656c6c6f[,password=passphrase]
-i=name=.key,file=payload.bin[,password=s3cr3t]
```

- `name` is required (PE names are limited by COFF constraints).
- Provide exactly one of `data` or `file`.
- Optional `password` encrypts payload contents.

### Overlay (`-l`)

```
-l=data=OVERLAY_BYTES[,password=secret]
-l=file=payload.bin[,password=secret]
```

- Appends payload after the executable image.
- Encryption semantics are the same as `-i`.

## 2. PE Handling

- Appends section headers with proper alignment.
- Updates section table metadata.
- Overlay metadata keeps extraction discoverable by analyzer/extractors.

## 3. ELF Handling

- Adds payload section metadata with alignment-aware offsets.
- Overlay appends data after loadable image content.

## 4. Force Mode

- Enables riskier flags/attributes for research workflows.

## 5. Testing

- CLI integration tests verify insertion/overlay presence and extraction roundtrip.
