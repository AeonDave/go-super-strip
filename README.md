# go-super-strip

Advanced executable manipulation tool for PE and ELF binaries with stripping, obfuscation, and section insertion capabilities.

- **File Analysis**: Comprehensive PE/ELF structure inspection
- **Section Stripping**: Remove debug symbols and unnecessary sections  
- **File Compaction**: Reduce executable size by removing sections
- **Obfuscation**: Randomize section names, base addresses, and metadata
- **Section Insertion**: Add encrypted hex-encoded data sections
- **Regex Stripping**: Remove bytes matching custom patterns
- **Encryption**: AES-256-GCM encryption for inserted sections

**Supported Formats**: PE (.exe, .dll) and ELF (Linux executables, shared libraries)

## Installation

```bash
git clone <repository-url>
cd go-super-strip
go build -o gosstrip.exe .
```

## Usage

```
gosstrip [OPTIONS] <file>
```

### Core Operations

| Option | Description |
|--------|-------------|
| `-a, --analyze` | Analyze file structure (read-only) |
| `-s, --strip` | Strip debug and symbol sections |
| `-c, --compact` | Remove sections to reduce file size |
| `-o, --obfuscate` | Apply obfuscation techniques |
| `-i, --insert <spec>` | Insert hex-encoded section |
| `-r, --regex <pattern>` | Strip bytes matching regex |
| `-f, --force` | Apply risky operations |
| `-v` | Verbose output |

### Operation Order
Operations execute in sequence: **insert** → **strip/compact** → **obfuscate** → **regex**

## Examples

### File Analysis
```bash
# Analyze PE/ELF structure
gosstrip -a program.exe
gosstrip -a -v ./binary
```

### Basic Operations
```bash
# Strip debug sections
gosstrip -s program.exe

# Compact file size
gosstrip -c program.exe  

# Apply obfuscation
gosstrip -o program.exe

# Combined operations
gosstrip -s -c -o program.exe

# With risky operations
gosstrip -s -f program.exe
```

### Section Insertion
```bash
# Insert file as hex data
gosstrip -i "data:file.bin" program.exe

# Insert string as hex
gosstrip -i "msg:HelloWorld" program.exe

# Insert with encryption (string password)
gosstrip -i "secret:data.bin:password123" program.exe

# Insert with encryption (hex password)  
gosstrip -i "payload:config.dat:deadbeef1234" program.exe
```

### Regex Operations
```bash
# Remove specific patterns
gosstrip -r "UPX!" program.exe
gosstrip -r "golang.*" binary
```

## Section Insertion Format

**Syntax**: `name:data_or_file[:password]`

- **name**: Section name (max 8 chars for PE)
- **data_or_file**: File path or string data
- **password**: Optional encryption (string or hex format)

**Password**: Even-length hex strings are treated as hex passwords, others as string passwords.

## Security Features

- **AES-256-GCM encryption** for sensitive data
- **Overlay insertion** for corrupted/packed executables  
- **Corruption detection** with automatic fallback modes
- **Safe operation order** to prevent PE structure damage
