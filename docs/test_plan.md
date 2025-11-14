# Test Plan

This plan outlines the new automated tests that will be added under `/test` to validate the
core helper utilities that power CLI and packing workflows.

## Common Utilities
- **Formatting helpers**: Cover `FormatOperationResult` and `CategorizeDetails` to ensure
  operation summaries highlight categorized details and gracefully handle empty data.
- **Cryptographic helpers**: Exercise `ProcessStringForInsertion`, `ProcessFileForInsertion`,
  and `DecryptAES256GCM` so encrypted payloads round-trip correctly for both plain-text and
  hexadecimal passwords.
- **General helpers**: Validate entropy calculations, pattern matching, size/permission
  formatting, entropy color thresholds, truncation, and section name sanitisation via
  `common` package exports. These utilities feed directly into analysis and reporting
  features described in the README.

## CLI-Oriented Safety Nets
- **Operation planning**: Reaffirm that `plannedOperations` keeps packing as the final step
  when multiple switches are set. (Already has unit coverage in `main_test.go`; new tests will
  reference the exported helpers instead of duplicating private assertions.)

All new tests will live in `/test`, reference the exported APIs from their respective
packages, and assert behaviour that aligns with the documented tool capabilities rather than
its current incidental implementation details.
