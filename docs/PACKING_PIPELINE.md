# PACKING PIPELINE & POLYMORPHISM

This document describes the `-p` packer, its options, and how the polymorphic stub works. It complements `test_polymorphism.sh`.

## 1. CLI Grammar

```
-p=compression=xz,encryption=aes-256-gcm,polymorphic=true,inmemory=auto
```

Options (comma-separated key/value pairs):

| Option | Values | Description |
|--------|--------|-------------|
| `compression` | `xz`, `lzma`, `none` | Algorithm used before encryption. |
| `encryption` | `aes-256-gcm`, `chacha20`, `none` | Protects payload at rest. |
| `polymorphic` | `true/false` | Picks a random stub variant and randomizes control flow. |
| `inmemory` | `off`, `auto`, `memfd`, `process_hollowing`, `atomic_bombing`, `self_injection`, `stealth_loader` | Linux supports `memfd`; Windows exposes the full set. `auto` picks the safest strategy per platform and payload architecture (32-bit payloads default to `self_injection`). |
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
- **In-memory execution:** Linux uses `memfd_create` + `fexecve`; Windows exposes several modes:
  - `process_hollowing`: suspended sacrificial process, `NtUnmapViewOfSection`, `WriteProcessMemory`, `SetThreadContext`.
  - `atomic_bombing`: chunks payloads into atoms, rebuilds via a hidden window, injects through the APC flow.
  - `self_injection`: reflectively maps the payload inside the current process (32-bit and 64-bit aware).
  - `stealth_loader`: disables ETW/AMSI, pins the payload buffer, uses raw `NtAllocateVirtualMemory` / `NtCreateThreadEx`, and keeps execution inside the original process for minimal telemetry.
- **Instruction padding:** stub assembler contains randomized NOP sled density.

## 4. In-Memory Strategy Summary

| Mode | Availability | Notes |
|------|--------------|-------|
| `off` | Linux & Windows | Writes decrypted payload to disk, executes, cleans up when `cleanup=true`. |
| `memfd` | Linux | Fileless execution via `memfd_create` + `fexecve`, falls back to temp files when the syscall fails. |
| `process_hollowing` | Windows | Suspended sacrificial process, `NtUnmapViewOfSection`, `WriteProcessMemory`, `SetThreadContext`, resume thread. |
| `atomic_bombing` | Windows | Atom-based staging (chunks payload, rebuilds via hidden window) before the APC-based injector copies the payload in. |
| `self_injection` | Windows | Reflectively maps the payload in the current process and applies relocations/imports (supports both PE32 and PE32+ payloads). |
| `stealth_loader` | Windows | Disables ETW/AMSI, pins payload buffers, allocates executable memory via `NtAllocateVirtualMemory`, launches threads with `NtCreateThreadEx`, never spawns child processes (best for write-restricted environments). |

`auto` selects `memfd` on Linux and the safest Windows strategy for the payload architecture (32-bit payloads default to `self_injection` unless `stealth_loader` is explicitly requested). Unsupported combinations fall back to `off`.

## 5. Output Files

- Default: overwrite the input and leave the packed stub there.
- With output path: writes `<output>` and leaves the original untouched.
- `.packed` suffix is no longer auto-generated; tests should target the explicit output when needed.

## 6. Testing

- `test_polymorphism.sh` validates uniqueness and execution. Run quick mode during CI.
- CLI integration tests exercise a basic pack run to ensure the stub prefix is present.
- Manual validation: run `gosstrip -p=... binary` then execute the output on both Windows and Linux to ensure anti-debug features behave as expected.
