# go-super-strip

Advanced executable stripping and obfuscation tool for PE and ELF binaries.

## Overview

go-super-strip is a comprehensive binary manipulation tool that provides advanced stripping, obfuscation, regex-based byte removal, and section insertion capabilities for Windows PE and Linux ELF executables. It offers detailed analysis and reporting for each operation performed.

## Features

### Core Operations
- **Debug/Symbol Stripping**: Remove debug information and symbol tables to reduce file size
- **Advanced Obfuscation**: Apply multiple obfuscation techniques including section name randomization, base address randomization, and metadata obfuscation
- **Regex Byte Stripping**: Remove specific byte patterns matching regular expressions
- **Section Insertion**: Add custom sections with data from external files
- **Comprehensive Analysis**: Detailed binary structure analysis with entropy calculations and security assessments

### Supported File Formats
- **PE Files**: Windows executables (.exe), dynamic libraries (.dll)
- **ELF Files**: Linux/Unix executables and shared libraries

### Advanced Features
- Detailed operation reporting with success/failure status
- Entropy analysis for packed/encrypted section detection
- Hash verification (MD5, SHA1, SHA256) for integrity checking
- Robust error handling with descriptive messages
- Verbose logging for debugging and analysis

## Installation

### Prerequisites
- Go 1.18 or later
- Windows (for PE files) or Linux/WSL (for ELF files)

### Build from Source
```bash
git clone <repository-url>
cd go-super-strip
go build -o go-super-strip main.go
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
| `-i <spec>` | `--insert <spec>` | Add section (format: name:filepath) |
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
go-super-strip -s program.exe

# Apply obfuscation techniques only
go-super-strip -o program.exe

# Remove bytes matching regex pattern
go-super-strip -r "golang.*" binary
```

### Combined Operations
```bash
# Strip and obfuscate
go-super-strip -s -o program.exe

# Strip, obfuscate, and add custom section
go-super-strip -s -o -i "payload:data.bin" program.exe

# Full processing pipeline with regex
go-super-strip -s -o -r "debug" -i "custom:config.dat" binary
```

### Advanced Usage
```bash
# Insert multiple sections (requires multiple runs)
go-super-strip -i "data:payload.bin" program.exe
go-super-strip -i "config:settings.json" program.exe

# Verbose processing with all operations
go-super-strip -v -s -o -r "test.*" -i "final:data.bin" binary
```

## Output and Reporting

The tool provides detailed reporting for each operation:

```
Processing file: program.exe
File type: PE
=== Strip Operations ===
Stripping debug sections...
Strip debug sections: APPLIED (removed 5 sections, saved 245KB)
=== Obfuscation Operations ===
Obfuscating section names...
Obfuscate section names: APPLIED (renamed 12 sections)
=== Insert Operations ===
Adding section 'payload' from file: data.bin
Add section: APPLIED (added 1024 bytes)
Completed operations: strip, obfuscate, insert
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

## Error Handling

The tool provides descriptive error messages and suggested solutions:

```
Error: failed to add section: invalid section name format
Suggestion: Use format 'name:filepath' (e.g., 'data:payload.bin')

Error: file has no section headers - cannot add sections
Suggestion: File may be packed or corrupted. Try analysis mode first.
```

## Performance

### Typical Processing Times
- **Analysis**: < 1 second for files up to 100MB
- **Stripping**: 1-5 seconds depending on file size and section count
- **Obfuscation**: 2-10 seconds for complex binaries
- **Section Insertion**: < 1 second per section

### Memory Usage
- Efficient streaming for large files
- Memory usage typically 2-3x file size during processing
- Automatic cleanup of temporary data

## Security Considerations

### Use Cases
- Malware analysis and research (controlled environments)
- Binary size optimization for embedded systems
- Security research and education
- Anti-reverse engineering techniques

### Responsible Usage
- Only use on files you own or have explicit permission to modify
- Test modified binaries thoroughly before deployment
- Maintain backups of original files
- Comply with local laws and regulations

## Troubleshooting

### Common Issues

**File not recognized as PE/ELF**
- Verify file is not corrupted
- Check file has proper headers
- Use analysis mode to inspect structure

**Operation skipped with "no sections found"**
- File may already be stripped
- Use analysis mode to verify current state
- Some files have minimal section tables

**Modified binary doesn't execute**
- Obfuscation may have been too aggressive
- Critical sections may have been modified
- Try operations individually to isolate issues

### Debug Information

Use the `-v` flag for detailed operation logs:
```bash
go-super-strip -v -s -o program.exe
```

## Development

### Building
```bash
go mod tidy
go build -ldflags="-s -w" -o go-super-strip main.go
```

### Testing
```bash
# Test on sample binaries
go test ./...

# Integration testing with real binaries
go run main.go -a test_binary
```

### Architecture
- `main.go`: Command-line interface and operation orchestration
- `perw/`: PE file handling and manipulation
- `elfrw/`: ELF file handling and manipulation
- Modular design for easy extension and maintenance

## License

This project is provided for educational and research purposes. Users are responsible for compliance with applicable laws and regulations.

## Contributing

Contributions are welcome. Please ensure:
- Code follows Go best practices
- All operations include proper error handling
- New features include appropriate tests
- Documentation is updated for new functionality

## Changelog

### Current Version
- Complete ELF support with section insertion
- Advanced obfuscation techniques
- Comprehensive analysis with entropy calculations
- Regex-based byte pattern removal
- Detailed operation reporting
- Cross-platform compatibility (Windows/Linux)
