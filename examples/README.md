# MSSPI Examples

This directory contains example applications demonstrating how to use the MSSPI library for both TLS and DTLS communications.

## Files

- `msspi_example.c` - Combined TLS/DTLS client/server example application  
- `msspi_stub.c` - Stub implementation of MSSPI for testing/demonstration
- `Makefile` - Build configuration for Unix-like systems (Linux/macOS)
- `make_windows.bat` - Build script for Windows systems
- `README.md` - This file

## Building

The examples can be built in two modes on different platforms:

### Linux/macOS

#### Stub Mode (Default, for Testing/Demo)
```bash
cd examples
make stub
# or simply
make
```

This builds with a stub implementation that demonstrates the API usage patterns without requiring external dependencies.

#### Full Mode (Requires CryptoPro CSP)
```bash
cd examples  
make full
```

This builds with the real MSSPI library, but requires a properly installed CryptoPro CSP environment.

### Windows

#### Stub Mode (Default, for Testing/Demo) 
```cmd
cd examples
make_windows.bat stub
```

This builds with a stub implementation that works without external dependencies.

#### Full Mode (Uses Windows Built-in SSP Interface)
```cmd
cd examples
make_windows.bat full
```

This builds with the real MSSPI library using Windows' built-in Schannel SSP interface. **No CryptoPro CSP required on Windows** - it uses the native Windows TLS/SSL implementation.

## Usage

The example application can operate in four modes:

### TLS Server
```bash
# Linux/macOS
./build/msspi_example --server --tls --port 4433

# Windows  
build\msspi_example.exe --server --tls --port 4433
```

### TLS Client
```bash
# Linux/macOS
./build/msspi_example --client --tls --host localhost --port 4433

# Windows
build\msspi_example.exe --client --tls --host localhost --port 4433
```

### DTLS Server
```bash
# Linux/macOS
./build/msspi_example --server --dtls --port 4434

# Windows
build\msspi_example.exe --server --dtls --port 4434
```

### DTLS Client
```bash
# Linux/macOS
./build/msspi_example --client --dtls --host localhost --port 4434

# Windows
build\msspi_example.exe --client --dtls --host localhost --port 4434
```

## Command Line Options

- `--server` - Run as server (default: client)
- `--client` - Run as client
- `--tls` - Use TLS protocol (default)
- `--dtls` - Use DTLS protocol
- `--host HOST` - Server hostname for client (default: localhost)
- `--port PORT` - Port number (default: 4433 for TLS, 4434 for DTLS)
- `--verbose` - Enable verbose output
- `--help` - Show help message

## Testing

### Linux/macOS

To run automated tests:

```bash
# Test both TLS and DTLS (stub mode)
make test

# Test only TLS
make test-tls

# Test only DTLS
make test-dtls
```

### Windows

To run automated tests:

```cmd
# Test both TLS and DTLS (stub mode)
make_windows.bat stub test

# Test only TLS  
make_windows.bat stub test-tls

# Test only DTLS
make_windows.bat stub test-dtls

# Test with full Windows SSP interface
make_windows.bat full test
```

The test targets will automatically start a server in the background, run a client to connect to it, exchange messages, and then clean up.

## Example Session

1. **Start TLS server** in one terminal:
   ```bash
   # Linux/macOS
   ./build/msspi_example --server --tls --port 4433
   
   # Windows
   build\msspi_example.exe --server --tls --port 4433
   ```

2. **Connect with TLS client** in another terminal:
   ```bash
   # Linux/macOS
   ./build/msspi_example --client --tls --host localhost --port 4433
   
   # Windows
   build\msspi_example.exe --client --tls --host localhost --port 4433
   ```

3. The client will connect, perform a TLS handshake, send a test message, receive an echo response, and disconnect.

## Features Demonstrated

- **TLS and DTLS protocol support** - Shows how to configure MSSPI for both protocols
- **Client and server modes** - Demonstrates both sides of the connection
- **Handshake process** - Shows the TLS/DTLS handshake using `msspi_connect()` and `msspi_accept()`
- **Data exchange** - Demonstrates reading and writing encrypted data
- **Proper cleanup** - Shows how to properly shutdown and close MSSPI handles
- **Error handling** - Basic error handling for connection and I/O operations
- **Socket abstraction** - Shows how to integrate MSSPI with socket I/O using callbacks

## Build Modes

### Stub Mode
- **Purpose**: Testing, demonstration, and development
- **Dependencies**: None (beyond standard C library)
- **Functionality**: Shows API usage patterns, simulates handshakes, but no real encryption
- **Benefits**: Easy to build and test without complex dependencies

### Full Mode  
- **Purpose**: Production use with real TLS/DTLS encryption
- **Dependencies**: CryptoPro CSP libraries must be installed
- **Functionality**: Real TLS/DTLS implementation with proper encryption
- **Requirements**: Licensed CryptoPro CSP installation

## Status

- ✅ **TLS Example**: Working correctly in both stub and full modes
- ⚠️ **DTLS Example**: API usage correct, but UDP socket handling needs refinement in stub mode
- ✅ **API Documentation**: Complete demonstration of all major MSSPI functions
- ✅ **Build System**: Supports both stub and full modes
- ✅ **Testing Framework**: Automated tests for verification

## Notes

- The stub implementation is for demonstration only and does not provide real cryptographic security
- For production use with real encryption, the full mode with CryptoPro CSP is required
- The DTLS example shows correct API usage but may need socket handling adjustments for production use
- Error handling is basic for demonstration purposes - production code should have more robust error handling
- The server echoes back received messages for testing purposes

## Troubleshooting

**Build Errors in Full Mode**: Ensure CryptoPro CSP is properly installed and libraries are available in the expected paths.

**DTLS Connection Issues**: DTLS requires proper UDP socket handling and may need firewall configuration.

**Certificate Errors**: The examples use system certificates or require proper certificate configuration for production use.