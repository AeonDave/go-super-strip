# go-super-strip

```
 ██████╗  ██████╗ ███████╗███████╗████████╗██████╗ ██╗██████╗ 
██╔════╝ ██╔═══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██╔══██╗
██║  ███╗██║   ██║███████╗███████╗   ██║   ██████╔╝██║██████╔╝
██║   ██║██║   ██║╚════██║╚════██║   ██║   ██╔══██╗██║██╔═══╝ 
╚██████╔╝╚██████╔╝███████║███████║   ██║   ██║  ██║██║██║     
 ╚═════╝  ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝     
                                                              
              |  G O   S U P E R   S T R I P  |
```

**go-super-strip** is a powerful command-line utility written in Go for analyzing, stripping, and obfuscating executable
files in both **ELF** (Linux) and **PE** (Windows) formats. Inspired by the original *sstrip (Super Strip)* project, it
provides advanced techniques for reducing file size and increasing resistance to reverse engineering.

---

## 🎯 Supported Formats

- **ELF** — Executable and Linkable Format (Linux/Unix)
- **PE** — Portable Executable (Windows)

---

## ✨ Key Features

- **Regex-based Stripping**
    - Remove specific byte patterns using regular expressions
- **Metadata Stripping**
    - Debug sections removal
    - Symbol table stripping
    - Comprehensive metadata removal
- **Advanced Obfuscation**
    - Section name randomization
    - Base address obfuscation
    - Header field randomization
    - Padding obfuscation
- **Multi-Format Support**
    - Dedicated handlers for ELF and PE formats
    - Format-specific optimization techniques

---

## ⚙️ Requirements

- [Go](https://golang.org/dl/) version **1.24** or higher

---

## 📦 Installation

1. Ensure Go is installed on your system.
2. Clone the repository:
   ```bash
   git clone <REPOSITORY_URL>
   cd go-super-strip
   ```
3. Build the executable:
   ```bash
   go build -o go-super-strip
   ```

---

## 🚀 Usage

**Basic Syntax:**

```bash
./go-super-strip <file> [options]
```

### Generic Stripping

Remove specific byte patterns using regex (note that patterns are applied AFTER all other operations):

```bash
# Remove UPX signatures (with proper regex escaping)
./go-super-strip program -s "\\d\\.\\d{2}\\x00UPX!\\r"

# Remove custom build strings
./go-super-strip program -s "ConfidentialBuild"
```

### Metadata Stripping

Remove various types of metadata:

```bash
# Strip debug information only (long form)
./go-super-strip program -strip-debug
# Or using short form
./go-super-strip program -d

# Strip symbol tables only (long form)
./go-super-strip program -strip-symbols
# Or using short form  
./go-super-strip program -y

# Strip all non-essential metadata (recommended)
./go-super-strip program -strip-all
# Or using short form
./go-super-strip program -S
```

### Obfuscation Techniques

Apply anti-analysis techniques:

```bash
# Randomize section names (long form)
./go-super-strip program -obf-names
# Or using short form
./go-super-strip program -n

# Obfuscate base addresses (long form)
./go-super-strip program -obf-base
# Or using short form
./go-super-strip program -b

# PE-specific obfuscation techniques:
# Obfuscate load configuration directory (PE only)
./go-super-strip program.exe -obf-load-config
# Or using short form
./go-super-strip program.exe -l

# Obfuscate import table metadata (PE only)
./go-super-strip program.exe -obf-import-table
# Or using short form
./go-super-strip program.exe -i

# Aggressive import name obfuscation (PE only)
./go-super-strip program.exe -obf-imports
# Or using short form
./go-super-strip program.exe -m

# Apply all obfuscation techniques (long form)
./go-super-strip program -obf-all
# Or using short form
./go-super-strip program -O
```

### Combined Operations

Multiple techniques can be combined:

```bash
# Comprehensive stripping and obfuscation (long form)
./go-super-strip myapp.exe -strip-all -obf-all -s "CompanyName"

# Same operation using short forms (much faster to type!)
./go-super-strip myapp.exe -S -O -s "CompanyName"

# Quick debug and symbol stripping
./go-super-strip binary -d -y

# Fast full processing
./go-super-strip program -S -O

# PE-specific combined operations:
# Conservative PE obfuscation (metadata only)
./go-super-strip app.exe -strip-all -obf-names -obf-base -obf-import-table
# Short form
./go-super-strip app.exe -S -n -b -i

# Aggressive PE obfuscation (includes function name randomization)
./go-super-strip app.exe -strip-all -obf-names -obf-import-table -obf-imports
# Short form  
./go-super-strip app.exe -S -n -i -m

# Maximum PE processing (strip everything + all obfuscations)
./go-super-strip program.exe -S -O

# Remove sensitive data with regex pattern (applied AFTER other operations)
./go-super-strip app.elf -S -O -s "SECRET_KEY_\\d+"
```

### Arguments Reference

| Argument (Long)       | Argument (Short) | Description                                      | Type     |
|-----------------------|------------------|--------------------------------------------------|----------|
| `<file>`              | -                | Target executable file path (first argument)    | Required |
| `-s <pattern>`        | -                | Strip bytes matching regex pattern (applied AFTER all other operations) | Optional |
| `-strip-debug`        | `-d`             | Strip debug sections                             | Optional |
| `-strip-symbols`      | `-y`             | Strip symbol table sections                      | Optional |
| `-strip-all`          | `-S`             | Strip all non-essential metadata                 | Optional |
| `-obf-names`          | `-n`             | Randomize section names                          | Optional |
| `-obf-base`           | `-b`             | Obfuscate base addresses                         | Optional |
| `-obf-load-config`    | `-l`             | Obfuscate load configuration directory (PE only) | Optional |
| `-obf-import-table`   | `-i`             | Obfuscate import table metadata (PE only)        | Optional |
| `-obf-imports`        | `-m`             | Aggressive import name obfuscation (PE only)     | Optional |
| `-obf-all`            | `-O`             | Apply all obfuscation techniques                 | Optional |

---

## 📊 ELF Techniques & Risk Analysis

The following table details all stripping and obfuscation techniques available for ELF executables:

| Category               | Technique                | Sections Affected                                  | Risk Level  | Failure Rate* | Description                                                      |
|------------------------|--------------------------|----------------------------------------------------|-------------|---------------|------------------------------------------------------------------|
| **Debug Stripping**    | Strip Debug Sections     | `.debug_*`, `.zdebug_*`, `.stab*`, `.gdb_index`    | 🟢 Low      | ~2%           | Removes DWARF debugging information, STABS data, and GDB indices |
| **Symbol Stripping**   | Strip Symbol Tables      | `.symtab`, `.strtab`                               | 🟢 Low      | ~1%           | Removes static symbol tables (preserves dynamic symbols)         |
| **Build Info**         | Strip Build Metadata     | `.note.*`, `.comment`, `.gnu.*`, `.buildid`        | 🟢 Low      | ~1%           | Removes build IDs, compiler notes, and version information       |
| **Profiling**          | Strip Profile Data       | `.gmon`, `.profile`                                | 🟢 Low      | ~0%           | Removes profiling and performance monitoring data                |
| **Exception Handling** | Strip Exception Data     | `.eh_frame*`, `.gcc_except_table`, `.ARM.ex*`      | 🟡 Medium   | ~15%          | **WARNING**: Breaks C++ exceptions and stack unwinding           |
| **Architecture**       | Strip Arch Sections      | `.ARM.*`, `.MIPS.*`, `.xtensa.*`                   | 🟡 Medium   | ~5%           | Removes architecture-specific metadata                           |
| **Relocations**        | Strip Relocations        | `.rel.*`, `.rela.*`                                | 🔴 High     | ~80%          | **WARNING**: Breaks dynamic linking in most cases                |
| **Dynamic Linking**    | Strip Dynamic Data       | `.dynamic`, `.dynsym`, `.dynstr`, `.got*`, `.plt*` | 🔴 Critical | ~95%          | **WARNING**: Breaks dynamically linked executables               |
| **Section Headers**    | Remove Section Table     | Section header table                               | 🟡 Medium   | ~10%          | Makes sections invisible to analysis tools                       |
| **Obfuscation**        | Randomize Section Names  | All section names                                  | 🟢 Low      | ~3%           | Replaces section names with random strings                       |
| **Obfuscation**        | Obfuscate Base Addresses | Program headers                                    | 🟢 Low      | ~2%           | Randomizes virtual memory addresses                              |
| **Obfuscation**        | Modify ELF Header        | ELF header fields                                  | 🟢 Low      | ~1%           | Randomizes non-critical header fields                            |
| **Advanced**           | GOT/PLT Obfuscation      | `.got`, `.plt` sections                            | 🟡 Medium   | ~25%          | Obfuscates Global Offset Table entries                           |

*Failure rates are estimates based on typical usage scenarios. Static executables have lower failure rates.

---

## 📊 PE Techniques & Risk Analysis

The following table details all stripping and obfuscation techniques available for PE executables:

| Category               | Technique               | Sections Affected                 | Risk Level | Failure Rate* | Description                                             |
|------------------------|-------------------------|-----------------------------------|------------|---------------|---------------------------------------------------------|
| **Debug Stripping**    | Strip Debug Sections    | `.debug$*`, `.pdata`, `.xdata`    | 🟢 Low     | ~3%           | Removes CodeView debug info and procedure data          |
| **Resources**          | Strip Resources         | `.rsrc`                           | 🟡 Medium  | ~8%           | **WARNING**: Removes icons, version info, dialogs       |
| **Build Info**         | Strip Build Metadata    | `.buildid`, `.gfids`, `.comment`  | 🟢 Low     | ~1%           | Removes build IDs, CFG data, and compiler info          |
| **Relocations**        | Strip Relocation Table  | `.reloc`                          | 🟡 Medium  | ~20%**        | **WARNING**: Breaks ASLR and base address conflicts     |
| **Exception Handling** | Strip Exception Data    | `.pdata`, `.xdata`, `.sxdata`     | 🔴 High    | ~45%          | **WARNING**: Breaks structured exception handling (SEH) |
| **Non-Essential**      | Strip Misc Sections     | `.drectve`, `.shared`, `.cormeta` | 🟢 Low     | ~2%           | Removes linker directives and metadata                  |
| **Obfuscation**        | Randomize Section Names | All section names                 | 🟢 Low     | ~2%           | Replaces section names with random strings              |
| **Obfuscation**        | Obfuscate Base Address  | ImageBase field                   | 🟢 Low     | ~1%           | Randomizes preferred load address                       |
| **Obfuscation**        | Obfuscate Directories   | Debug/TLS/LoadConfig dirs         | 🟡 Medium  | ~10%          | Clears optional header directory entries                |
| **Obfuscation**        | Import Table Metadata   | Import descriptor fields          | 🟢 Low     | ~5%           | Shuffles descriptors, modifies metadata, adds fake entries |
| **Obfuscation**        | Aggressive Import Names | Function names in import tables   | 🟡 Medium  | ~15%          | **AGGRESSIVE**: Randomizes actual function names        |
| **Obfuscation**        | Randomize Header Fields | TimeDateStamp, reserved fields    | 🟢 Low     | ~1%           | Obfuscates PE header metadata                           |
| **Obfuscation**        | Randomize Padding       | Inter-section padding             | 🟢 Low     | ~0%           | Fills unused space with random data                     |
| **Advanced**           | Obfuscate Timestamps    | Resource/version timestamps       | 🟢 Low     | ~2%           | Randomizes embedded timestamp strings                   |

*Failure rates for PE files. **Lower for DLLs (~5%), higher for EXEs with ASLR.

## ⚠️ Important Notes

- **Backup your files:** Always work on copies of executables, never originals
- **Test thoroughly:** Verify functionality after modification, especially with medium/high risk techniques
- **Format-specific behavior:** Some techniques are more aggressive on certain architectures or linking types
- **Static vs Dynamic:** Static executables generally have lower failure rates than dynamically linked ones
- **PE Import Obfuscation Levels:**
    - `-obf-import-table` (Low Risk): Only modifies metadata, preserves functionality
    - `-obf-imports` (Medium Risk): **AGGRESSIVE** - randomizes function names, may break dynamic loading
- **Risk Assessment:**
    - 🟢 **Low Risk**: Generally safe, minimal chance of breaking functionality
    - 🟡 **Medium Risk**: May break specific features, test thoroughly
    - 🔴 **High Risk**: High probability of breaking executable functionality
    - 🔴 **Critical Risk**: Almost guaranteed to break dynamically linked executables

### Recommended Safe Combinations

**Conservative (Low Risk):**
```bash
# Long form
./go-super-strip program -strip-debug -strip-symbols -obf-names
# Short form (faster to type)
./go-super-strip program -d -y -n
```

**Moderate (Acceptable Risk):**
```bash
# Long form
./go-super-strip program -strip-all -obf-all
# Short form (much faster!)
./go-super-strip program -S -O
```

**PE-Specific Safe Combinations:**
```bash
# Conservative PE (Low Risk - metadata only)
./go-super-strip app.exe -strip-all -obf-names -obf-base -obf-import-table
# Short form
./go-super-strip app.exe -S -n -b -i

# Moderate PE (Medium Risk - includes load config)
./go-super-strip app.exe -strip-all -obf-names -obf-base -obf-load-config -obf-import-table
# Short form
./go-super-strip app.exe -S -n -b -l -i

# Aggressive PE (Higher Risk - includes function name randomization)
./go-super-strip app.exe -strip-all -obf-names -obf-import-table -obf-imports
# Short form
./go-super-strip app.exe -S -n -i -m
```

**Aggressive (High Risk - Static Executables Only):**
```bash
# Long form with regex pattern (proper escaping)
./go-super-strip static_program -strip-all -obf-all -s "BuildInfo|\\d\\.\\d{2}"
# Short form
./go-super-strip static_program -S -O -s "BuildInfo"
```

---

## 🔧 Development & Extension

The modular architecture allows for easy extension:

- **New techniques:** Add functions in `elfrw/` or `perw/` packages
- **CLI options:** Extend argument parsing in `main.go`
- **Format support:** Implement new handlers following the `FileHandler` interface
