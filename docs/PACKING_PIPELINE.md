# PACKING PIPELINE & POLYMORPHISM

This document describes the `-p` packer, its options, and how the polymorphic stub works. It complements `test_polymorphism.sh`.

## 1. CLI Grammar

```
-p=compression=xz,encryption=aes-256-gcm,polymorphic=true,inmemory=true,antidebug=true,antivm=true
```

Options (comma-separated key/value pairs):

| Option | Values | Description |
|--------|--------|-------------|
| `compression` | `xz`, `lzma`, `none` | Algorithm used before encryption. |
| `encryption` | `aes-256-gcm`, `chacha20`, `none` | Protects payload at rest. |
| `polymorphic` | `true/false` | Picks a random stub variant and randomizes control flow. |
| `inmemory` | `true/false` | Executes the payload directly from memory (memfd/process hollowing). |
| `antidebug` | `true/false` | Enables debugger detection hooks. |
| `antivm` | `true/false` | Adds VM heuristics (CPUID, timing). |
| `padding` | `true/false` | Adds junk data to the stub. |
| `level` | `1-9` | Compression effort (xz/lzma only). |

Packing mutates the working file unless an explicit `<output>` path is supplied.

## 2. Workflow

1. Strip/compact/obfuscate pipeline produces the working binary.
2. Packer encrypts the payload and embeds it into a Go stub.
3. Stub source is compiled on the fly; its `.text` contains polymorphic junk.
4. The encrypted payload plus metadata is appended to the stub.
5. Optional overlays (from `-l`) remain intact after packing.

## 3. Stub Techniques

- **Polymorphism:** random stub variant selection, variable renaming, garbage injection, control-flow flattening, and per-build AES key randomization.
- **Anti-debug/vm:** uses Windows API (IsDebuggerPresent, NtQueryInformationProcess) and Linux `/proc` checks plus timing loops.
- **In-memory execution:** Linux uses `memfd_create` + `fexecve`; Windows uses process hollowing with WriteProcessMemory + SetThreadContext.
- **Instruction padding:** stub assembler contains randomized NOP sled density.

## 4. Output Files

- Default: overwrite the input and leave the packed stub there.
- With output path: writes `<output>` and leaves the original untouched.
- `.packed` suffix is no longer auto-generated; tests should target the explicit output when needed.

## 5. Testing

- `test_polymorphism.sh` validates uniqueness and execution. Run quick mode during CI.
- CLI integration tests exercise a basic pack run to ensure the stub prefix is present.
- Manual validation: run `gosstrip -p=... binary` then execute the output on both Windows and Linux to ensure anti-debug features behave as expected.
