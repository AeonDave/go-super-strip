# STRIPPING TECHNIQUES (PE & ELF)

This note documents how `-s` rewrites Windows PE and Linux ELF binaries.

## 1. Purpose and Pipeline Context

Stripping is the first step in the canonical workflow:

```
strip -> compact -> obfuscate -> regex -> insert -> overlay -> extract
```

During strip we zero/random-fill sensitive metadata in place; structural header removal belongs to compaction.

## 2. Safety Modes

- **Default (safe)**: targets non-critical metadata (debug, symbols, build markers).
- **Force (`-s=force=true`)**: expands removals to riskier loader-visible structures.

All actions produce `StripAction` metadata so later stages can reason about changes.

## 3. Fill Overrides

`-s=fill=auto|zero|random` controls wipe style:

- `auto`: rule-defined behavior.
- `zero`: deterministic overwrite.
- `random`: randomized overwrite.

## 4. PE Techniques

- Section classification in `perw/strip_types.go`.
- Header hygiene in `perw/strip.go` (timestamps, Rich header handling, debug directory cleanup).
- Pattern scrubbing via built-in regex rules with protected ranges unless `force=true`.

## 5. ELF Techniques

- Section classification in `elfrw/strip_types.go`.
- Header and note cleanup in `elfrw/strip.go`.
- Pattern scrubbing with PT/critical-range guards unless `force=true`.

## 6. Validation

- `go test ./...`
- `test/cli_matrix.sh`
- deep analyze before/after snapshots for manual verification.
