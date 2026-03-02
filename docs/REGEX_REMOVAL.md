# REGEX REMOVAL STAGE

The `-r` flag removes user-specified byte patterns. In the pipeline, it runs after obfuscation and before insert/overlay/extract.

## 1. CLI Grammar

```
gosstrip ... -r=pattern=marker1,pattern='marker.*2' -r=fill=random,pattern=cleanup_rules.txt <input> [output]
```

- At least one `pattern` is required.
- Pattern values may be inline regexes or file paths (one regex per non-empty, non-comment line).
- `fill=zero|random` controls replacement bytes.
- `force=true` disables protected ranges.

## 2. Engine Behavior

- Scans the full byte stream.
- Replaces matches in place (no size/offset changes).
- Emits detailed operation messages (match counts and warnings).

## 3. Protections & Force Mode

When `force=false`, the engine skips matches overlapping protected ranges:

- **PE**: entrypoint page and import-sensitive regions.
- **ELF**: critical sections, PT_INTERP/PT_LOAD-sensitive ranges, and `.shstrtab`.

Set `force=true` to bypass protections for explicit cleanup runs.

## 4. Safety Guards

- Regex execution timeout.
- Max-match cap to avoid runaway patterns.

## 5. Testing

- `test/cli_cross_compile_test.go`
- PE/ELF operation tests under `test/`.
