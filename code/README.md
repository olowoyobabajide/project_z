# project_z: FS Analyzer

## Overview
FS Analyzer is a static analysis tool designed for security auditing of Android applications and Linux binaries. It specializes in examining `DEX` files (Android Dalvik Executables), `ELF` shared objects (`.so`), and `AndroidManifest.xml` files to identify potential security vulnerabilities, hardcoded secrets, and unsafe function usage.

## Key Features
- **DEX Analysis**: Scans Dalvik bytecode for suspicious patterns and security issues.
- **ELF Analysis (32/64-bit)**: Unified support for both 32-bit and 64-bit shared objects. Identifies unsafe function imports (e.g., `strcpy`, `system`) with aggregated usage counts.
- **Manifest Auditing**: Analyzes `AndroidManifest.xml` for exported components and risky permissions.
- **Secret Detection**: Regex-based scanning for hardcoded API keys, tokens, and private keys.
- **JSON Reporting**: Generates detailed, machine-readable reports including forensic evidence and risk levels.

## Prerequisites
The project depends on the following libraries:
- **libxml2**: Used for parsing Android XML manifests.
- **OpenSSL**: Used for hash calculations and digest operations.

### Installing Dependencies (Linux/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install libxml2-dev libssl-dev pkg-config
```

## Compilation
To compile the project, use the following `gcc` command from the root directory:

```bash
gcc -I. *.c src/*.c -o fs_analyzer $(pkg-config --cflags --libs libxml-2.0) -lssl -lcrypto
```

## Usage
Run the analyzer by providing the path to the extracted APK directory or file system location:

```bash
./fs_analyzer <path_to_analyze> [-o json <report_file.json>]
```

### Example
```bash
./fs_analyzer ./temp -o json report.json
```

## Troubleshooting & Potential Errors
- **Missing libxml-2.0**: If you get an error like `libxml/parser.h: No such file or directory`, ensure `libxml2-dev` is installed and that `pkg-config` is correctly finding the flags.
- **OpenSSL Linkage**: Ensure `-lssl -lcrypto` are at the end of your `gcc` command to resolve cryptographic functions.
- **Permission Denied**: Some operations (like scanning certain directories) might require read permissions. If analyzing system files, you may need `sudo`.
- **delete.sh**: On exit, the program attempts to execute `delete.sh`. Ensure this file exists and is executable (`chmod +x delete.sh`), or the program will report an execution error at the very end.

## Session Analysis
For a living log of recent technical changes and refactors performed during development, see [session_analysis.json](./session_analysis.json).
