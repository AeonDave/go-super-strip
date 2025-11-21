# In-Memory Execution Strategies

This note complements `PACKING_PIPELINE.md` by describing every execution mode in detail, listing strengths and weaknesses, and highlighting gaps that still need work.
Every packed binary contains only the loader code needed for the resolved architecture/mode. When a fallback happens, the packer prints a warning and embeds the fallback runtime instead of linking every strategy.

## Technique Matrix

| Mode | Platform / Arch | Stealth ★ (1–5) | Reliability ★ | Why these scores | Notes |
|------|-----------------|-----------------|----------------|------------------|-------|
| `off` | Linux/Windows (x86/x64) | ★☆☆☆☆ | ★★★★★ | Writes temp file; easiest to spot but always runs. | Safe fallback when everything else fails; leaves disk artifacts. |
| `memfd` | Linux (x86/x64) | ★★★☆☆ | ★★★★☆ | Fileless, minimal surface; depends on kernel/seccomp support. | Uses `memfd_create` + `fexecve`. Defeated if seccomp forbids `memfd` or older kernels. |
| `process_hollowing` | Windows (x86/x64) | ★★☆☆☆ | ★★★★☆ | Child process + classic APIs make it noisy; generally stable. | Errors if suspended-process creation fails. |
| `atomic_bombing` | Windows (x86/x64) | ★★★☆☆ | ★★☆☆☆ | Avoids WPM but uses GUI atoms/message pump; fragile and slower. | Requires a GUI thread; errors otherwise. |
| `early_bird` | Windows (x86/x64) | ★★★★☆ | ★★★★☆ | Runs before original image; APC-visible but no GUI dependency. | Errors if APC setup fails. |
| `early_bird_atomic_bombing` | Windows (x86/x64) | ★★★★☆ | ★★★☆☆ | Early Bird timing plus atom staging; more moving parts. | Errors if APC queueing fails. |
| `process_doppelganging` | Windows (x86/x64) | ★★☆☆☆ | ★★☆☆☆ | TxF/SEC_IMAGE lowers disk artifacts but TxF is brittle and signatured. | Errors if transaction/section creation fails. |
| `transacted_hollowing` | Windows (x86/x64) | ★★☆☆☆ | ★★☆☆☆ | Similar TxF dependence; reliability tied to transaction support. | Errors if transaction handling fails. |
| `self_injection` | Windows (x86/x64) | ★★★☆☆ | ★★★★★ | No child process; uses normal VAlloc/Protect so moderately visible; very stable. | Available everywhere. |
| `nt_syscall_reflective` | Windows (x86/x64) | ★★★★☆ | ★★★★☆ | Raw NT syscalls + ETW/AMSI patching improve stealth; may hit syscall hooks. | Errors if raw NT syscalls are blocked. |
| `reflective_loader` | Windows (x86/x64) | ★★★★★ | ★★★☆☆ | Minimal footprint/imports; fewer safety checks reduce reliability. | Errors when thread creation fails. |

Legend: more ★ means better stealth/success. Reliability reflects how often the loader works on modern systems; TxF-based methods are less reliable on hardened hosts.

## Mode Details

### `off`
- **How it works:** decrypts payload to a temp file, executes it, and removes the file when `cleanup=true`.
- **Advantages:** Guaranteed to work; no special privileges needed.
- **Disadvantages:** Leaves disk artifacts, easiest to detect, noisy command-line traces.
- **Use when:** targeting extremely hardened boxes where reflective loaders fail.

### `memfd`
- **How it works:** `memfd_create` → write payload → `fexecve`, so nothing touches disk.
- **Advantages:** Fileless, standard Linux kernel syscall, survives restricted `/tmp`.
- **Disadvantages:** Older kernels or seccomp profiles may block `memfd`. Each run creates a unique anonymous file descriptor, complicating caching.

### `process_hollowing`
- **How it works:** spawn suspended process (e.g., `notepad.exe`), unmap its image with `NtUnmapViewOfSection`, write new payload, fix thread context, resume.
- **Advantages:** Compatible with most AV bypass playbooks; easy to analyze/troubleshoot.
- **Disadvantages:** Highly signatured by EDR, requires process creation privileges, spawns a visible child.

### `atomic_bombing`
- **How it works:** chunk payload into atoms (`GlobalAddAtomW`), read them through a hidden window procedure, inject via APC.
- **Advantages:** Avoids `WriteProcessMemory`, less obvious API footprint, supports suspended processes.
- **Disadvantages:** Complex, slower, requires GUI thread/message pump.

### `early_bird`
- **How it works:** create a suspended sacrificial process, map the packed payload into it, queue the payload entry point as an APC (Early Bird), then resume the thread so our code runs before the original image.
- **Advantages:** Simple suspended-process flow without atom staging; runs before the target binary initializes; no GUI dependency.
- **Disadvantages:** Still visible through APC monitoring, and if the payload returns the sacrificial image will continue.

### `early_bird_atomic_bombing`
- **How it works:** creates a suspended sacrificial process, maps the payload like process hollowing, and queues the payload entry point as an APC (Early Bird) before resuming the thread.
- **Advantages:** No GUI requirement, executes before the original image starts, lets operators compare Early Bird vs classic atomic flows.
- **Disadvantages:** Still relies on APC instrumentation and assumes the payload never returns (otherwise the sacrificial image resumes).

### `self_injection`
- **How it works:** reflective loader maps PE32/PE32+ directly inside the current process, rewrites relocations/import table, jumps to entry point.
- **Advantages:** Works for both architectures, no child processes, decent stealth.
- **Disadvantages:** Still uses Win32 APIs (VirtualAlloc/Protect), so instrumentation sees suspicious memory changes. GC pinning is needed for Go (already handled).

### `nt_syscall_reflective`
- **How it works:** ensures GC + goroutine locking, disables ETW/AMSI, allocates executable memory via `NtAllocateVirtualMemory`, launches via `NtCreateThreadEx`, and keeps everything inside the original process.
- **Advantages:** No child processes, minimal API surface, ETW+AMSI bypass bundled, good for write-restricted hosts.
- **Disadvantages:** Larger stub (many imports), depends on Nt syscalls (may be hooked), requires admin for best results.

### `reflective_loader`
- **How it works:** stripped-down loader inspired by go-loader/Doge-MemX. Locks OSThread, disables GC, pins payload buffer, maps sections manually, calls `NtCreateThreadEx`.
- **Advantages:** Small binary footprint, randomizable imports, best stealth/resilience against signature-based detection.
- **Disadvantages:** Fewer safety checks, no fallback to process hollowing, no built-in telemetry patching.

## UAC Bypass
On Windows, every stub (regardless of mode) now attempts the `fodhelper.exe` registry hijack:

1. `NetUserGetInfo` verifies the current user has local admin privileges (priv=2).
2. If supported (Win8.1+/Server 2012 R2+), set `HKCU\Software\Classes\ms-settings\shell\open\command` values to point to our stub (`DelegateExecute` empty).
3. Launch `cmd.exe /C fodhelper`, which immediately runs the registered handler elevated.
4. Delete the registry values and exit the non-elevated instance.

If any step fails the stub simply continues at medium integrity, so payloads still execute.

## Strategy Assessment

### Still Useful
- `memfd` is the only fileless option for Linux (keep/improve).
- `self_injection` is the most compatible Windows technique, and now serves as the safety net for every architecture.
- `nt_syscall_reflective` and `reflective_loader` provide modern stealth features; we should keep expanding their NT-syscall coverage and shrink imports further.

### Aging / Noisy
- `process_hollowing` is noisy but still needed for defenders' test cases. Consider adding `CreateProcessAsUser` support to blend with child processes or letting users point to arbitrary sacrificial binaries.
- `atomic_bombing` is complex and fragile. It may be better to replace it with a more modern suspended-thread injector (e.g., Early Bird APC / `QueueUserAPC` with `SuspendThread`).

### Missing Capabilities / Next Steps
1. **Direct Syscall layer:** our stealth/reflective loaders still route through NTDLL exports. Adopting an indirection layer (e.g., syswhispers-style) would further shrink the import table.
2. **Kernel callback awareness:** add heuristics to detect EDR userland hooks and patch/unhook automatically.
3. **Signed stub option:** allow embedding an Authenticode signature or user-provided certificate to reduce static AV hits.
4. **Linux eBPF-aware loader:** memfd currently assumes no kernel tracing; consider adding `seccomp-bpf` detection or fallback to `pivot_root`-style execution.
5. **Atomic replacement:** replace the existing atom-based loader with a more stable technique (e.g., using Section Objects + `NtMapViewOfSection`) to avoid GUI dependencies.
6. **Reflective DLL execution:** add a DLL-specific mode to invoke exported functions after reflection (useful for goffloader/Doge modules).

By prioritizing reflective/self-injection improvements, trimming imports per mode, and optionally integrating direct syscalls/signing, we can shrink the stub further and reduce AV detections across all strategies.
