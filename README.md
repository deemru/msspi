# MSSPI - Micro Security Support Provider Interface

[![version](https://img.shields.io/github/release/deemru/msspi.svg)](https://github.com/deemru/msspi/releases/latest)
[![windows](https://img.shields.io/badge/windows-supported-brightgreen.svg)](https://github.com/deemru/msspi)
[![linux](https://img.shields.io/badge/linux-supported-brightgreen.svg)](https://github.com/deemru/msspi)
[![macos](https://img.shields.io/badge/macos-supported-brightgreen.svg)](https://github.com/deemru/msspi)
[![ios](https://img.shields.io/badge/ios-supported-brightgreen.svg)](https://github.com/deemru/msspi)
[![mingw](https://img.shields.io/badge/mingw-supported-brightgreen.svg)](https://github.com/deemru/msspi)

A cross-platform C library that provides a high-level interface for TLS/DTLS operations using Windows SChannel or compatible implementations.

## Features

- **OpenSSL-compatible API**: Core functions are interchangeable with OpenSSL counterparts
- **Cross-platform**: Windows, Linux, macOS, iOS, and MinGW support
- **TLS/DTLS support**: TLS 1.0-1.3 and DTLS 1.2 for secure connections
- **CAPIX support**: Crypto API Proxy - deferred loading of cryptographic libraries without compile-time linking
- **Smart card support**: PIN caching and hardware token integration

## Documentation

- [MSSPI](MSSPI.md) - Core TLS/DTLS functions
- [MSSPI_CERT](MSSPI_CERT.md) - Certificate parsing functions
- [CHANGELOG](CHANGELOG.md) - Version history and changes

## Real-World Usage

MSSPI powers TLS/SSL implementations in various projects across different ecosystems:

| Project | Language | Purpose | Repository |
|---------|----------|---------|------------|
| **Chromium-Gost** | C++ | Browser cryptography with GOST support | [deemru/Chromium-Gost](https://github.com/deemru/Chromium-Gost) |
| **stunnel-msspi** | C | Enhanced SSL tunneling | [CryptoPro/stunnel-msspi](https://github.com/CryptoPro/stunnel-msspi) |
| **go-msspi** | Go | Go crypto framework integration | [deemru/go-msspi](https://github.com/deemru/go-msspi) |
| **Qt OpenSSL Backend** | C++ | Qt framework SSL backend | [deemru/qtbase](https://github.com/deemru/qtbase) |

### Key Integration Patterns

- **Browser Integration**: Seamless TLS handshake switching between different crypto libraries
- **Tunneling**: Enhanced SSL/TLS proxying with Windows cryptography
- **Language Bindings**: Native TLS support for Go applications
- **Framework Backends**: Drop-in SSL backend for Qt applications

## Building

### Windows
Builds a DLL with certificate parsing support:
```cmd
cd build_windows
make.bat
```
This creates `msspi.dll` with full functionality including certificate parsing.

### Linux
Build static libraries:
```bash
cd build_linux
make
```
Available targets:
- `make` or `make all` - Build all static libraries
- `make static` - Build basic library (`libmsspi.a`)
- `make static-capix` - Build with CAPIX support (`libmsspi-capix.a`) for CryptoPro GOST cryptography
- `make shared` - Build shared library (`libmsspi.so`)
- `make clean` - Clean build artifacts

**Build options:**
- `MSSPI_USE_MSSPI_CERT` - Include certificate parsing functionality
- `MSSPI_USE_CAPIX` - Enable Crypto API Proxy (CAPIX) for deferred loading of cryptographic libraries

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read the documentation and ensure your changes maintain API compatibility.
