# project_z: FS Analyzer

## Overview
FS Analyzer is a static analysis tool designed for security auditing of Android applications and Linux binaries. It specializes in examining `DEX` files (Android Dalvik Executables), `ELF` shared objects (`.so`), and `AndroidManifest.xml` files to identify potential security vulnerabilities, hardcoded secrets, and unsafe function usage.

## Key Features
- **In-Memory APK Analysis**: Direct analysis of APK files using memory-backed streams. No temporary file extraction required.
- **DEX Analysis**: Scans Dalvik bytecode for suspicious patterns and security issues.
- **ELF Analysis (32/64-bit)**: Unified support for both 32-bit and 64-bit shared objects. Identifies unsafe function imports (e.g., `strcpy`, `system`) and sensitive regex patterns.
- **Manifest Auditing**: Analyzes `AndroidManifest.xml` for exported components and risky permissions using in-memory AXML decoding.
- **Security Flagging**: Detects SUID bits, world-writable files, and hidden files within the package.
- **Unified JSON Reporting**: All findings (Permissions, ELF, DEX, Hashes) are consolidated into a single machine-readable report.

> [!IMPORTANT]
> **Contextual Analysis Required**: These findings represent potential vulnerabilities and patterns that should be cross-referenced with the application's intended purpose. A detection (e.g., use of `system()`) is an indicator of risk, but not necessarily a harmful vulnerability in all contexts.


## Prerequisites
The project uses the following libraries:
- **libxml2**: Used for parsing Android XML manifests.
- **OpenSSL**: Used for hash calculations. Most Linux distributions include this by default, but you may need the development headers (`libssl-dev`).
- **libzip**: Used for high-performance ZIP archive handling. The core source is included in `src/dep`, but the library itself must be installed on the system to link correctly (e.g., `libzip-dev`).
- **pkg-config**: Used to retrieve valid compilation and linker flags for dependencies.

### Installing Dependencies (Optional/If Missing)
If your system lacks the necessary headers or libraries, you can install them via your package manager:

```bash
sudo apt-get update
sudo apt-get install libxml2-dev libssl-dev libzip-dev pkg-config
```

## Compilation
To compile the project, use the following `gcc` command from the root directory:

```bash
gcc -I. -Isrc -Isrc/dep *.c src/*.c src/dep/*.c -o fs_analyzer $(pkg-config --cflags --libs libxml-2.0) -lssl -lcrypto -lzip
```

## Usage
Run the analyzer by providing the path to the source APK file:

```bash
./fs_analyzer <path_to_apk> [-d] [-o json <report_file.json>]
```

### Flags
- `-o json <filename>`: (Required for structured output) Saves all findings to a JSON file.
- `-d`: Enables detailed, legacy-style DEX logging to `dexLog.txt` for debugging purposes.
- `-h`, `--help`: Displays the help message and usage instructions.
- `-v`, `--version`: Displays the current version of the tool.

### Example
```bash
./fs_analyzer /path/to/apk/JohnDoe.apk -o json report.json
```

## Troubleshooting & Potential Errors
- **Missing libxml-2.0**: If you get an error like `libxml/parser.h: No such file or directory`, ensure `libxml2-dev` is installed and that `pkg-config` is correctly finding the flags.
- **OpenSSL Linkage**: Ensure `-lssl -lcrypto` are at the end of your `gcc` command to resolve cryptographic functions.


