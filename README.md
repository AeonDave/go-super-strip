# Go Super Strip

## Advanced Binary Manipulation Tool

Go Super Strip (gosstrip) is a powerful  tool designed for advanced manipulation of PE and ELF binary executables.

### Key Features

- **Binary Analysis**: Deep inspection of PE/ELF file structures, sections, and metadata
- **Debug Information Removal**: Strip symbols, debug sections, and unnecessary metadata
- **Size Optimization**: Compact binaries by removing non-essential sections
- **Binary Hardening**: Apply various obfuscation techniques to protect against reverse engineering
- **Custom Data Integration**: Insert and encrypt custom data sections or overlays
- **Pattern Removal**: Strip bytes matching custom regex patterns
- **Secure Encryption**: AES-256-GCM encryption for sensitive data sections

### Supported File Formats

- **PE Files**: Windows executables (.exe), dynamic-link libraries (.dll)
- **ELF Files**: Linux executables, shared objects (.so), and other ELF format binaries

## Installation

### Build from Source

```bash
# Clone the repository
git clone this
# Navigate to the project directory
cd go-super-strip
# Build the executable
go build
```

## Usage Guide

The basic command syntax is:

```
gosstrip [OPTIONS] <file_path>
```

### Core Operations

| Option                  | Description                                                |
|-------------------------|------------------------------------------------------------|
| `-a, --analyze`         | Analyze file structure (read-only operation)               |
| `-s, --strip`           | Strip debug symbols and unnecessary sections               |
| `-c, --compact`         | Reduce file size by removing non-essential sections        |
| `-o, --obfuscate`       | Apply obfuscation techniques to hinder reverse engineering |
| `-i, --insert <spec>`   | Insert custom hex-encoded section                          |
| `-l, --overlay <spec>`  | Add data as overlay                                        |
| `-r, --regex <pattern>` | Strip bytes matching custom regex pattern                  |
| `-f, --force`           | Enable risky operations (use with -s, -c, or -o)           |
| `-v`                    | Enable verbose output                                      |
| `-h`                    | Display help information                                   |

### Operation Execution Order

Operations are always executed in the following sequence to ensure file integrity:

1. **Stripping** (-s)
2. **Compaction** (-c)
3. **Obfuscation** (-o)
4. **Section/Overlay Insertion** (-i, -l)
5. **Regex Operations** (-r)

## Examples

### File Analysis

```bash
# Basic file structure analysis
gosstrip -a program.exe
```

### Binary Optimization

```bash
# Strip debug sections
gosstrip -s program.exe

# Compact file size
gosstrip -c program.exe  

# Apply obfuscation techniques
gosstrip -o program.exe

# Full optimization pipeline
gosstrip -s -c -o program.exe

# With risky operations enabled
gosstrip -s -f program.exe
```

### Data Insertion

```bash
# Insert file content as a new section
gosstrip -i "data:file.bin" program.exe

# Insert string data as a new section
gosstrip -i "msg:HelloWorld" program.exe

# Insert encrypted section with string password
gosstrip -i ".sec:data.bin:password123" program.exe

# Insert encrypted section with hex password
gosstrip -i "payload:config.dat:deadbeef1234" program.exe

# Add file as overlay
gosstrip -l "data.bin" program.exe

# Add encrypted overlay
gosstrip -l "data.bin:password123" program.exe
```

### Pattern Removal

```bash
# Remove UPX packer signatures
gosstrip -r "UPX!" program.exe

# Remove Go compiler artifacts
gosstrip -r "golang.*" binary

# Combined with other operations
gosstrip -s -c -r "UPX!" program.exe
```

## Technical Details

### Section Insertion Format

**Syntax**: `name:data_or_file[:password]`

- **name**: Section name (limited to 8 characters for PE files)
- **data_or_file**: Either a file path or literal string data
- **password**: Optional encryption password (string or hex format)

**Note**: Even-length hex strings are treated as hex passwords, others as string passwords.

### Overlay Format

**Syntax**: `data_or_file[:password]`

- **data_or_file**: Either a file path or literal string data
- **password**: Optional encryption password (string or hex format)