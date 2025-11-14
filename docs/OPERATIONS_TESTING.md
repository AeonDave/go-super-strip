# Operations Coverage and Integration Testing

This document complements the existing stripping, compaction, and obfuscation technique guides by detailing the end-to-end
coverage that now exists for both ELF and PE workflows. Each test exercises the real helper packages rather than mocks so we
can detect regressions in binary manipulation behaviour early.

## Test Matrix

| Operation          | ELF Coverage                                                     | PE Coverage                                                      |
|--------------------|------------------------------------------------------------------|------------------------------------------------------------------|
| Reading            | `TestELFPipelineOperations` validates `elfrw.ReadELF` on fixtures | `TestPEPipelineOperations` validates `perw.ReadPE` on fixtures    |
| Analysis           | `elfrw.AnalyzeELF` invoked in integration pipeline               | `perw.AnalyzePE` invoked in integration pipeline                 |
| Stripping          | Asserts strip applies and keeps binary valid                     | Asserts strip applies and keeps binary valid                     |
| Compaction         | Ensures compaction reports results without corrupting file       | Ensures compaction reports results without corrupting file       |
| Obfuscation        | Forces obfuscation path and asserts result applied               | Forces obfuscation path and asserts result applied               |
| Section Insertion  | Inserts marker section and verifies presence                     | Inserts marker section and verifies presence                     |
| Regex Removal      | Removes inserted marker and verifies absence                     | Removes inserted marker and verifies absence                     |
| Packing            | Uses stubbed compiler to run `pack.Pack` and inspect output      | Uses stubbed compiler to run `pack.Pack` and inspect output      |

## Fixture Notes

* Both ELF and PE flows compile `testfiles/simple_go.go` on the fly so the repository does not need to store prebuilt
  binaries. The ELF suite cross-builds for Linux and still skips on non-Linux hosts where the toolchain helpers are not
  available.
* Packing tests override stub compilation via `pack.SetStubCompilerForTests` so that end-to-end packing can run inside the
  test suite without launching an additional Go toolchain.

## Adding New Coverage

When new binary operations are introduced, extend the matrix above and update the integration tests in `/test` to ensure both
ELF and PE pipelines still reflect production behaviour. Keeping tests in sync with the docs makes it trivial to verify that
features are exercised across formats.
