# Go-SStrip

Go-SStrip is a Go rewrite of the sstrip (Super Strip) project, designed to remove as much non-essential data as possible from ELF files without affecting their memory image.

## Features

- Remove all non-essential information from ELF executables
- Optionally remove trailing zero bytes
- Modular structure for easy extension with new stripping/obfuscation techniques
- Compatible with Linux (and potentially other platforms)
- Fine-grained CLI: each stripping/cleaning/obfuscation function can be enabled via a short or long flag
- Automated test suite to verify which flags may break ELF files

## Stripping and Obfuscation Functions

Implemented in `elfrw/strip.go`:

- **StripSectionTable**: Removes the ELF section header table references
- **StripNonLoadable**: Removes non-loadable segments
- **RandomizeSectionNames**: Randomizes section names in the section header string table
- **StripSectionsByNames**: Generic function to remove sections by name or prefix
- **StripAllMetadata**: Removes all metadata (symbols, strings, debug, build info, profiling, exception, arch, PLT/reloc)
- **StripDynamicLinking**: Removes dynamic linking sections
- **ZeroFill**: Overwrites section data with zeros
- **ReadBytes**: Reads raw bytes from the ELF file

### Section Groups (for fine-grained stripping)
- **SymbolsSectionsExact**: Symbol tables
- **StringSectionsExact**: String tables
- **DebugSectionsExact/Prefix**: Debug info
- **BuildInfoSectionsExact/Prefix**: Build/toolchain info
- **ProfilingSectionsExact**: Profiling/statistics
- **ExceptionSectionsExact**: Exception/stack unwinding
- **ArchSectionsPrefix**: Architecture-specific
- **PLTRelocSectionsExact/Prefix**: PLT/relocation

## Requirements

- Go 1.20 or newer
- The `github.com/yalue/elf_reader` library for ELF parsing

## Installation

1. Clone the repository
2. Ensure Go is installed
3. Install the dependency: `go get github.com/yalue/elf_reader`
4. Build the project: `go build -o go-sstrip`

## Usage

```
go-sstrip [OPTIONS] FILE...
```

Options:

```
  -z, --zeroes        Also remove trailing zero bytes
  -s, --stripSectionTable   Remove the section table (header)
  -d, --stripDebug          Remove debug sections
  -y, --stripSymbols        Remove symbol tables
  -t, --stripStrings        Remove string tables
  -n, --stripNonLoadable    Remove non-loadable segments
  -r, --randomizeNames      Randomize section names
  -b, --stripBuildInfo      Remove build/toolchain info sections
  -p, --stripProfiling      Remove profiling/statistics sections
  -e, --stripException      Remove exception/stack unwinding sections
  -a, --stripArch           Remove architecture-specific sections
  -l, --stripPLTReloc       Remove PLT/relocation sections
  -A, --stripAll            Apply all stripping techniques
      --help          Show help and exit
      --version       Show version information and exit
```

## Testing

Automated tests are provided in `test/TestStrippingFlags_test.go`:
- Place working ELF binaries in `test_bins/`
- Run `go test ./test`
- Each stripping function is applied to each binary, and the result is checked for ELF validity
- Output files are saved in `test_out/` with a suffix indicating the flag used

## Extending

To add new stripping or obfuscation techniques:
1. Add new functions in `elfrw/strip.go`
2. Integrate them into the CLI in `main.go`
3. Optionally, add new tests in `test/TestStrippingFlags_test.go`
