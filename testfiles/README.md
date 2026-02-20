# testfiles

This directory contains **curated fixture sources** and (optionally) prebuilt binaries used for regression testing.

## Sources (`testfiles/src/`)

These are intentionally *non-trivial* programs so ELF/PE transformations have real metadata to work with.

| File | Language | Intent |
|------|----------|--------|
| `src/go_kitchen_sink.go` | Go | I/O + hashing + small HTTP fail-fast (no external dependency) |
| `src/go_sensor_aggregator.go` | Go | Concurrency + math + deterministic output |
| `src/c_kitchen_sink.c` | C | libc usage (math/stdio/string/malloc/file I/O) |
| `src/c_sensor_stats.c` | C | deterministic parsing + stats |

## Prebuilt binaries

Some workflows prefer checking in prebuilt fixtures (including UPX variants). These are generated from the sources above.

**Naming convention (recommended):**
- `pe_amd64_<lang>_<name>.exe`
- `elf_amd64_<lang>_<name>`
- UPX-packed variants: append `_upx`

Example:
- `elf_amd64_c_kitchen_sink`
- `elf_amd64_c_kitchen_sink_upx`
- `pe_amd64_go_sensor_aggregator.exe`

## Notes
- Tests should never rely on in-place mutation: always run `gosstrip <flags> <input> <output>` and validate input is unchanged.
- ELF execution on Windows requires WSL.
