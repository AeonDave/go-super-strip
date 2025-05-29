``` markdown
# GosStrip

GosStrip is a command-line tool written in Go, inspired by the sstrip (Super Strip) project. It is designed to analyze, strip, and obfuscate executable files in ELF (commonly used on Linux) and PE (Portable Executable, used on Windows) formats. The goal is to reduce file sizes by removing non-essential data and/or to make analysis and reverse engineering more complex.

## Supported Formats

*   **ELF** (Executable and Linkable Format)
*   **PE** (Portable Executable)

## Key Features

*   **File Analysis (`info`):** Displays basic information about the executable, such as a list of sections and segments.
*   **Stripping (`strip`):** Removes various types of non-essential data to reduce file size:
    *   Debug information.
    *   Symbol tables.
    *   An `all` option for comprehensive stripping of non-essential metadata.
*   **Obfuscation (`obfuscate`):** Applies techniques to make the executable harder to analyze:
    *   Randomization of section names.
    *   Obfuscation of base addresses (if applicable to the format).
    *   An `all` option for comprehensive obfuscation.
*   **Multi-Format Support:** Handles both ELF and PE files through dedicated handlers.
*   **Command-Line Interface (CLI):** Clear and simple for specifying the file, command, and desired options.

## Requirements

*   Go (version 1.24 or newer, as per the current development environment)

## Installation

1.  Ensure you have Go installed on your system.
2.  Clone this repository:
    ```bash
    git clone <REPOSITORY_URL>
    cd gosstrip
    ```
3.  Build the project:
    ```bash
    go build -o gosstrip
    ```
    This will create an executable named `gosstrip` in the current directory.

## Usage

The primary use of GosStrip is via the command line, specifying the file to process, the command to execute, and any relevant options.
```
bash ./gosstrip -file <path_to_executable> -cmd  [command_options]
command
``` 

### Main Commands

#### 1. `info`
Displays detailed information about the specified executable file.

**Syntax:**
```
bash ./gosstrip -file <file_path> -cmd info
``` 
**Example:**
```
bash ./gosstrip -file ./my_elf_program -cmd info ./gosstrip -file C:\Path\To\my_program.exe -cmd info
``` 

#### 2. `strip`
Removes non-essential data from the executable file.

**Syntax:**
```
bash ./gosstrip -file <file_path> -cmd strip -strip <strip_options>
``` 
**Options for `-strip` (comma-separated, no spaces):**
*   `debug`: Removes debug sections and information.
*   `symbols`: Removes symbol tables.
*   `all`: Applies all available stripping techniques for the file format (generally includes debug, symbols, and other non-critical metadata).

**Examples:**
```
bash ./gosstrip -file ./my_elf_program -cmd strip -strip debug,symbols ./gosstrip -file ./my_elf_program -cmd strip -strip all ./gosstrip -file C:\Path\To\my_program.exe -cmd strip -strip all
``` 

#### 3. `obfuscate`
Applies obfuscation techniques to the executable file.

**Syntax:**
```
bash ./gosstrip -file <file_path> -cmd obfuscate -obf <obf_options>
``` 
**Options for `-obf` (comma-separated, no spaces):**
*   `names`: Randomizes section names in the file.
*   `base`: Attempts to obfuscate base addresses (effectiveness and availability may depend on the file format and structure).
*   `all`: Applies all available obfuscation techniques.

**Examples:**
```
bash ./gosstrip -file ./my_elf_program -cmd obfuscate -obf names ./gosstrip -file C:\Path\To\my_program.exe -cmd obfuscate -obf names,base ./gosstrip -file ./my_elf_program -cmd obfuscate -obf all
``` 

### General Options

*   `-file <path>`: **(Required)** Path to the executable file to process.
*   `-cmd <command>`: **(Required)** Command to execute. Possible values: `info`, `strip`, `obfuscate`.
*   `-strip <opts>`: Specific options for the `strip` command.
*   `-obf <opts>`: Specific options for the `obfuscate` command.
*   `-h`: Shows a help message with syntax and examples.

### Other Usage Examples
```
bash ./gosstrip -h # Show help ./gosstrip -file a.out -cmd info ./gosstrip -file a.out -cmd strip -strip all ./gosstrip -file a.exe -cmd obfuscate -obf names,base
``` 

## Testing

**Important:** Modifying executable files is an inherently risky operation that can lead to file corruption if not performed correctly.

No information about an automated test suite is available from the provided files. For a tool of this nature, it is **critical** to implement and maintain a robust test suite that includes:
*   A variety of valid ELF and PE files (both 32-bit and 64-bit, executables, and libraries).
*   Checks to ensure that modified files are still valid according to their format specifications.
*   Where possible, functional tests to ensure that modified executables (especially after non-aggressive stripping) still work as intended.
*   Tests for edge cases and error handling (e.g., corrupted files or unsupported formats).

It is strongly recommended to thoroughly test any modifications on copies of files, never on originals.

## Extending GosStrip

The code structure in `main.go` with the `FileHandler` interface and specific handlers (`ELFHandler`, `PEHandler`) facilitates extension:

1.  **New Techniques:** Add new stripping or obfuscation functions within the `elfrw` (for ELF) or `perw` (for PE) packages and then integrate them into the respective `Strip` or `Obfuscate` methods of the handlers.
2.  **New Options:** Modify the `parseOptions` function and the command logic in `main.go` to support new options for stripping or obfuscation.
3.  **Support New Formats:**
    *   Create a new package for managing the format (e.g., `machorw` for Mach-O).
    *   Implement a new struct that satisfies the `FileHandler` interface.
    *   Update the `detectFormat` function in `main.go` to identify the new format.

Remember to add appropriate tests for any new functionality or changes.
```
