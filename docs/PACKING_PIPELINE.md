# PACKING PIPELINE & POLYMORPHISM

This document describes the `-p` packer, its options, and how the polymorphic stub works. It complements `test/pack_matrix.ps1`.

## 1. CLI Grammar

```
-p=compression=zlib,encryption=aes-256-gcm,polymorphic=true,inmemory=auto
```

Options (comma-separated key/value pairs):

| Option | Values | Description |
|--------|--------|-------------|
| `compression` | `zlib`, `none` | Algorithm used before encryption. |
| `encryption` | `aes-256-gcm`, `chacha20`, `none` | Protects payload at rest. |
| `polymorphic` | `true/false` | Picks a random stub variant and randomizes control flow. |
| `inmemory` | `off`, `auto`, `memfd`, `process_hollowing`, `atomic_bombing`, `early_bird`, `early_bird_atomic_bombing`, `process_doppelganging`, `transacted_hollowing`, `self_injection`, `nt_syscall_reflective`, `reflective_loader` | Linux supports `memfd`; Windows exposes the full set. `auto` picks the safest strategy per platform and payload architecture (32-bit payloads default to `self_injection`). |
| `padding` | `true/false` | Adds junk data to the stub. |
| `level` | `0-9` | Compression effort (zlib only). |

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
  - `process_doppelganging`: transaction-based hollowing path (currently shares runtime with hardened hollowing).
  - `transacted_hollowing`: hollowing via transacted source (currently shares runtime with hardened hollowing).
  - `self_injection`: reflectively maps the payload inside the current process (32-bit and 64-bit aware).
  - `nt_syscall_reflective`: disables ETW/AMSI, pins the payload buffer, uses raw `NtAllocateVirtualMemory` / `NtCreateThreadEx`, and keeps execution inside the original process for minimal telemetry.
- **Mode-specific compilation:** `GetPEStubSource` / `GetELFStubSource` splice only the routines needed for the chosen architecture + mode, so no unused loader code ships inside the stub.
- **Instruction padding:** stub assembler contains randomized NOP sled density.

## 4. In-Memory Strategy Summary

| Mode | Availability | Notes |
|------|--------------|-------|
| `off` | Linux & Windows | Writes decrypted payload to disk, executes, cleans up when `cleanup=true`. |
| `memfd` | Linux | Fileless execution via `memfd_create` + `fexecve`, falls back to temp files when the syscall fails. |
| `process_hollowing` | Windows | Suspended sacrificial process, `NtUnmapViewOfSection`, `WriteProcessMemory`, `SetThreadContext`, resume thread. |
| `atomic_bombing` | Windows | Atom-based staging (chunks payload, rebuilds via hidden window) before the APC-based injector copies the payload in. |
| `early_bird` | Windows | Suspended-process injection that maps the payload and queues its entry point as an APC (Early Bird) before the original image runs. |
| `early_bird_atomic_bombing` | Windows | Same Early Bird flow but stages the payload via atom strings/window messages for telemetry comparisons. |
| `self_injection` | Windows | Reflectively maps the payload in the current process and applies relocations/imports (supports both PE32 and PE32+ payloads). |
| `nt_syscall_reflective` | Windows | Disables ETW/AMSI, pins payload buffers, allocates executable memory via `NtAllocateVirtualMemory`, launches threads with `NtCreateThreadEx`, never spawns child processes (best for write-restricted environments). |
| `reflective_loader` | Windows | Minimal reflective loader (inspired by go-loader/Doge-MemX). Disables GC, pins the payload buffer, maps it inside the current process, and launches it with `NtCreateThreadEx`. |

`auto` selects `memfd` on Linux and the safest Windows strategy for the detected architecture. Each loader now has dedicated PE32/PE32+ runtimes; unsupported mode requests now fail instead of silently falling back.

## 5. Stub Footprint & Option Impact

| Option | Physical impact on the stub | Notes |
|--------|-----------------------------|-------|
| `compression` | None | Only the payload blob shrinks/grows before encryption. |
| `encryption` | + key/nonce bytes (≤44 B) | The decryptor lives in the stub, but only the selected algorithm’s metadata is appended. |
| `polymorphic=true` | +0.5–3 KB Go helper (random) | Density/regperm/CF-mutation/instrsubst toggle how much junk code the generator injects; higher settings emit larger, more unique helper functions anchored via `init()`. |
| `padding=true` | None | Random padding is added to the payload, not the stub. |
| `inmemory=…` | Swaps runtime code | Only the implementation for the resolved mode/arch is compiled. Switching from `off` to `nt_syscall_reflective` replaces the entire runtime instead of stacking them. |
| `cleanup=false`, `verbose=true`, `params=…` | None | These only change behavior at runtime or CLI logging. |

Thanks to mode-specific compilation, PE32 builds stay minimal (tens of KB) unless you explicitly opt into a heavier runtime such as `nt_syscall_reflective`. Enabling polymorphism is the main lever that increases stub size/entropy; use a lower junk density if you need a smaller binary.

### UAC Bypass
Before any Windows loader runs the stub automatically attempts a *fodhelper.exe* bypass:

1. Call `NetUserGetInfo` to confirm the current user has local-admin privileges.
2. Write `HKCU\Software\Classes\ms-settings\shell\open\command` with the packed stub path and set an empty `DelegateExecute`.
3. Execute `cmd.exe /C fodhelper` hidden; `fodhelper.exe` runs the registered handler with high integrity.
4. Remove the registry values and exit the original process while the elevated instance continues.

If any step fails (non-admin, hardened UAC, etc.) the stub simply runs at the existing integrity level. All in-memory strategies benefit from elevation (suspended process creation, raw NT syscalls, etc.) but do not depend on it.

## 6. Output Files

- Default: overwrite the input and leave the packed stub there.
- With output path: writes `<output>` and leaves the original untouched.
- `.packed` suffix is no longer auto-generated; tests should target the explicit output when needed.

## 7. Testing

- `test/pack_matrix.ps1` (Windows) exhaustively validates stub uniqueness and execution across all option combinations. Run it after any change to `pack/`.
- CLI integration tests exercise a basic pack run to ensure the stub prefix is present.
- Manual validation: run `gosstrip -p=... binary` then execute the output on both Windows and Linux to ensure anti-debug features behave as expected.
