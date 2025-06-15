# go-super-strip

Advanced executable stripping and obfuscation tool for PE and ELF binaries.

## Overview

go-super-strip is a comprehensive binary manipulation tool that provides advanced stripping, obfuscation, regex-based byte removal, and hexadecimal section insertion capabilities for Windows PE and Linux ELF executables. It supports optional AES-256-GCM encryption for inserted sections and offers detailed analysis and reporting for each operation performed.

### Supported File Formats
- **PE Files**: Windows executables (.exe), dynamic libraries (.dll)
- **ELF Files**: Linux/Unix executables and shared libraries

## Installation

### Build from Source
```bash
git clone <repository-url>
cd go-super-strip
go build -o go-super-strip .
```

## Usage

### Basic Syntax
```
go-super-strip [OPTIONS] <file>
```

### Command Line Options

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-s` | `--strip` | Strip debug and symbol sections |
| `-o` | `--obfuscate` | Apply obfuscation techniques |
| `-r <pattern>` | `--regex <pattern>` | Strip bytes matching regex pattern |
| `-a` | `--analyze` | Analyze file structure (read-only) |
| `-i <spec>` | `--insert <spec>` | Add hex section (format: name:filepath or name:filepath:password) |
| `-v` | | Enable verbose output |
| `-h` | | Show help message |

### Operation Order
Operations are executed in a fixed sequence for predictable results:
1. **Strip** operations (debug/symbol removal)
2. **Obfuscation** operations (randomization and metadata changes)
3. **Regex** operations (pattern-based byte removal)
4. **Insert** operations (section addition)

## Examples

### Analysis and Inspection
```bash
# Analyze PE file structure
go-super-strip -a program.exe

# Analyze ELF binary with verbose output
go-super-strip -a -v ./binary
```

### Basic Operations
```bash
# Strip debug sections only
go-super-strip -s program

# Apply obfuscation techniques only
go-super-strip -o program

# Remove bytes matching regex pattern
go-super-strip -r "golang.*" binary

# Insert file as hex data (like xxd)
go-super-strip -i "payload:data.bin" program.exe
```

## Section Insertion with Hexadecimal Encoding

The `-i/--insert` option supports hex section insertion with optional encryption:

**Formats:**
- `name:filepath` - Insert file as hexadecimal data (like `xxd` output)
- `name:filepath:password` - Insert file as encrypted hexadecimal data

### Password Formats

- **String password**: `"mypassword"` - any regular string
- **Hex password**: `"deadbeef1234"` - hexadecimal string (even length, hex characters only)

### Examples

```bash
# Insert as hex data only (like xxd)
go-super-strip -i "payload:data.bin" program.exe

# Insert with string password (hex + encryption)
go-super-strip -i "payload:data.bin:mypassword" program.exe

# Insert with hex password (hex + encryption)
go-super-strip -i "secret:config.dat:deadbeef1234" program.exe

# Combined operations with hex insertion
go-super-strip -s -o -i "encrypted:payload.bin:secret123" binary
```

## Analysis Output

The analysis mode (`-a`) provides comprehensive binary information:

### File Information
- File format (PE/ELF) and architecture
- File size and entry point
- Endianness and platform details

### Section Analysis
- Section count and detailed properties
- Size, offset, and permission flags
- Entropy calculations for security assessment
- Hash values (MD5, SHA1, SHA256) for integrity

### Security Assessment
- Packed/encrypted section detection
- Entropy statistics and distribution
- Space analysis for modification potential

### Segment Analysis (ELF)
- Program header information
- Loadable segments and permissions
- Memory layout analysis

## Technical Details

### PE File Support
- **Sections**: .text, .data, .rdata, .rsrc, debug sections
- **Operations**: Section stripping, name obfuscation, import table modifications
- **Analysis**: Import/export tables, resource analysis, entropy calculations

### ELF File Support
- **Sections**: .text, .data, .rodata, .bss, debug sections (.debug_*)
- **Operations**: Section/symbol stripping, header obfuscation, section insertion
- **Analysis**: Program headers, segment analysis, symbol table examination

### Obfuscation Techniques
- Section name randomization with cryptographically secure generators
- Base address randomization for ASLR simulation
- Metadata obfuscation (timestamps, version info)
- Padding insertion between sections
- Header field obfuscation (non-critical fields)

### Safety Features
- Pre-operation validation to prevent corruption
- Backup recommendations for critical files
- Detailed error reporting with recovery suggestions
- Operation rollback on critical failures

## Limitations and Considerations

### General Limitations
- Packed executables may require unpacking before processing
- Code signing will be invalidated after modification
- Some obfuscation techniques may affect runtime behavior

### PE Specific
- Import Address Table (IAT) modifications may break some protections
- Resource modifications may affect application appearance
- .NET assemblies require special handling

### ELF Specific
- Dynamic linking information must be preserved
- Go runtime may be sensitive to address randomization
- Stripped binaries lose debugging capabilities

### Debug Information

Use the `-v` flag for detailed operation logs:
```bash
go-super-strip -v -s -o program.exe
```
