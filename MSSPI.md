# MSSPI API Documentation

## Overview

MSSPI (Micro Security Support Provider Interface) is a C library that provides a high-level interface for TLS/DTLS operations using Windows SChannel or compatible implementations. It supports both client and server modes, certificate management, and various TLS/DTLS features.

**OpenSSL Compatibility:** The core API functions ([`msspi_connect()`](#msspi_connect), [`msspi_accept()`](#msspi_accept), [`msspi_read()`](#msspi_read), [`msspi_write()`](#msspi_write), [`msspi_shutdown()`](#msspi_shutdown), [`msspi_peek()`](#msspi_peek)) are designed to be interchangeable with their OpenSSL counterparts (e.g., `SSL_connect`, `SSL_accept`, `SSL_read`, `SSL_write`, `SSL_shutdown`, `SSL_peek`), making it easier to migrate code between the two libraries.

## CAPIX Support

When `MSSPI_USE_CAPIX` is defined during compilation, MSSPI includes support for Crypto API Proxy (CAPIX). CAPIX provides deferred loading of cryptographic libraries, enabling access to additional cryptographic providers without requiring compile-time linking.

**Key features of CAPIX:**
- **Deferred loading**: Libraries are loaded at runtime, not compile time
- **Fallback support**: Graceful degradation when libraries are unavailable
- **Cross-platform**: Supports Windows, Linux, macOS, and other platforms

CAPIX allows applications to optionally use additional cryptographic providers when available, while maintaining compatibility with standard implementations.

## API Design

### Return Value Convention

Following OpenSSL style, most functions return `int` with the following convention:
- **`1`**: Success
- **`0`**: Failure

**Notable exceptions:**

1. **Functions returning non-`int` types:**
   - [`msspi_open()`](#msspi_open): `MSSPI_HANDLE` (or `NULL` on failure)
   - [`msspi_version()`](#msspi_version): `uint32_t` (library version)
   - [`msspi_last_error()`](#msspi_last_error): `uint32_t` (additional error code)

2. **Functions where `1` has specific meaning:**
   - [`msspi_connect()`](#msspi_connect) / [`msspi_accept()`](#msspi_accept): Handshake completes successfully

3. **Functions where `0` doesn't always mean failure:**
   - [`msspi_peek()`](#msspi_peek): Returns `0` when no data is buffered (check [`msspi_last_error()`](#msspi_last_error) to distinguish from actual errors)
   - [`msspi_pending()`](#msspi_pending): Returns `0` when no data is buffered (normal condition, not an error)

4. **Functions that can return `-1` when operation would block:**
   - [`msspi_connect()`](#msspi_connect)
   - [`msspi_accept()`](#msspi_accept)
   - [`msspi_shutdown()`](#msspi_shutdown)
   - [`msspi_read()`](#msspi_read)
   - [`msspi_peek()`](#msspi_peek)
   - [`msspi_write()`](#msspi_write)

5. **Functions returning positive numbers with specific meaning:**
   - [`msspi_read()`](#msspi_read) / [`msspi_peek()`](#msspi_peek) / [`msspi_write()`](#msspi_write): Number of bytes processed
   - [`msspi_pending()`](#msspi_pending): Number of bytes available for reading
   - [`msspi_state()`](#msspi_state): Bitmask of flags

### Error Reporting

On failure, call [`msspi_last_error()`](#msspi_last_error) to retrieve the Windows error code:

```c
uint32_t msspi_last_error(void);
```

This is analogous to OpenSSL's `ERR_get_error()` but returns Windows-specific error codes. Common error codes include:
- `ERROR_INVALID_HANDLE`: Invalid handle
- `ERROR_BAD_ARGUMENTS`: Invalid arguments
- `ERROR_NOT_FOUND`: Resource not found
- `ERROR_NOT_SUPPORTED`: Feature not supported
- `ERROR_INTERNAL_ERROR`: Internal error

### Thread Safety

The library is not thread-safe. Each handle should be used by a single thread. Multiple handles can be used concurrently in different threads.

### Memory Management

- Handles must be closed with [`msspi_close()`](#msspi_close) to free resources
- Pointers returned by getter functions (e.g., [`msspi_get_peercerts()`](#msspi_get_peercerts), [`msspi_get_alpn()`](#msspi_get_alpn)) are valid until the handle is closed or the connection state changes
- The library manages all internal memory allocations

### Function Call Order

The order of functions in the header file is **intentional and important**. Functions are grouped to indicate the recommended call sequence:

**Setup Phase:**

1. **Handle creation** - [`msspi_open()`](#msspi_open) creates a new handle
2. **Basic configuration** - [`msspi_set_client()`](#msspi_set_client), [`msspi_set_dtls()`](#msspi_set_dtls) set operation mode
3. **DTLS-specific** - [`msspi_set_dtls_peeraddr()`](#msspi_set_dtls_peeraddr), [`msspi_set_dtls_mtu()`](#msspi_set_dtls_mtu) if using DTLS
4. **Credential-affecting parameters** - [`msspi_set_version()`](#msspi_set_version), [`msspi_set_cipherlist()`](#msspi_set_cipherlist), [`msspi_set_hostname()`](#msspi_set_hostname), [`msspi_set_peerauth()`](#msspi_set_peerauth), [`msspi_set_cachestring()`](#msspi_set_cachestring) **must be called before certificate functions** as they affect credential caching
5. **Supporting configuration** - [`msspi_set_alpn()`](#msspi_set_alpn), [`msspi_set_certstore()`](#msspi_set_certstore), [`msspi_set_credprovider()`](#msspi_set_credprovider), [`msspi_set_pin_cache()`](#msspi_set_pin_cache), [`msspi_set_cert_cb()`](#msspi_set_cert_cb)
6. **Certificate loading** - [`msspi_set_mycert()`](#msspi_set_mycert), [`msspi_add_mycert()`](#msspi_add_mycert), [`msspi_set_mycert_pfx()`](#msspi_set_mycert_pfx), [`msspi_add_mycert_pfx()`](#msspi_add_mycert_pfx), [`msspi_set_mycert_options()`](#msspi_set_mycert_options) **call LAST** to avoid cache mismatches

**Connection Phase:**

7. **Handshake** - [`msspi_connect()`](#msspi_connect) (client) or [`msspi_accept()`](#msspi_accept) (server) establishes the connection
8. **Verification** - [`msspi_get_verify_status()`](#msspi_get_verify_status) and [`msspi_get_peercert_in_store_status()`](#msspi_get_peercert_in_store_status) verify peer certificate (optional, call after handshake)

**Data Transfer Phase:**

9. **Query functions** - `msspi_get_*()` functions retrieve connection information (version, ciphers, certificates, etc.)
10. **I/O operations** - [`msspi_read()`](#msspi_read), [`msspi_peek()`](#msspi_peek), [`msspi_write()`](#msspi_write) transfer data
11. **State monitoring** - [`msspi_pending()`](#msspi_pending), [`msspi_state()`](#msspi_state) check connection state

**Teardown Phase:**

12. **Shutdown** - [`msspi_shutdown()`](#msspi_shutdown) gracefully closes the connection
13. **Cleanup** - [`msspi_close()`](#msspi_close) frees all resources

**Note:** Violating the setup order (especially calling certificate functions before credential-affecting parameters) may result in credential cache mismatches or unexpected behavior.

## API Reference

---

### msspi_version

```c
uint32_t msspi_version(void);
```

Returns the library version.

**Returns:** Version number encoded as: `(major << 16) | (minor << 8) | patch`

---

### msspi_is_version_supported

```c
int msspi_is_version_supported(int version);
```

Checks if a TLS/DTLS version is supported by the system.

**Parameters:**
- `version`: Protocol version constant

**Returns:** `1` if supported, `0` otherwise

### Protocol Version Constants

```c
#ifndef TLS1_VERSION
#define TLS1_VERSION 0x0301
#endif

#ifndef TLS1_1_VERSION
#define TLS1_1_VERSION 0x0302
#endif

#ifndef TLS1_2_VERSION
#define TLS1_2_VERSION 0x0303
#endif

#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION 0x0304
#endif

#ifndef DTLS1_2_VERSION
#define DTLS1_2_VERSION 0xFEFD
#endif
```

---

### msspi_is_cipher_supported

```c
int msspi_is_cipher_supported(int cipher, int dtls);
```

Checks if a cipher suite is supported.

**Parameters:**
- `cipher`: Cipher suite ID
- `dtls`: `1` to check DTLS support, `0` for TLS

**Returns:** `1` if supported, `0` otherwise

---

### msspi_open

```c
MSSPI_HANDLE msspi_open(void *cb_arg, msspi_read_cb read_cb, msspi_write_cb write_cb);
```

Creates a new MSSPI handle.

**Parameters:**
- `cb_arg`: User argument passed to callbacks
- `read_cb`: Read callback function (analogous to OpenSSL's `BIO_read`)
- `write_cb`: Write callback function (analogous to OpenSSL's `BIO_write`)

**Callback signatures:**
```c
typedef int (*msspi_read_cb)(void *cb_arg, void *buf, int len);
typedef int (*msspi_write_cb)(void *cb_arg, const void *buf, int len);
```

**Read callback:**
- Called when the library needs to read data from the network
- Should read up to `len` bytes into `buf` from the underlying transport (e.g., socket)
- Reads TLS/DTLS protocol data (handshake messages, encrypted application data, alerts, etc.)
- **Returns:** Number of bytes read (>0), `0` on EOF/connection closed, or `-1` when would block
- Equivalent to OpenSSL's `BIO_read` - use the same implementation pattern

**Write callback:**
- Called when the library needs to write data to the network
- Should write `len` bytes from `buf` to the underlying transport (e.g., socket)
- Writes TLS/DTLS protocol data (handshake messages, encrypted application data, alerts, etc.)
- **Returns:** Number of bytes written (>0), `0` on error/connection closed, or `-1` when would block
- Equivalent to OpenSSL's `BIO_write` - use the same implementation pattern

**Returns:** Handle on success, `NULL` on failure

---

### msspi_set_client

```c
int msspi_set_client(MSSPI_HANDLE h, int enable);
```

Configures client or server mode.

**Parameters:**
- `h`: Handle
- `enable`: `1` for client mode, `0` for server mode

**Returns:** `1` on success, `0` on failure

---

### msspi_set_dtls

```c
int msspi_set_dtls(MSSPI_HANDLE h, int enable);
```

Enables or disables DTLS mode.

**Parameters:**
- `h`: Handle
- `enable`: `1` to enable DTLS, `0` for TLS

**Returns:** `1` on success, `0` on failure

---

### msspi_set_dtls_peeraddr

```c
int msspi_set_dtls_peeraddr(MSSPI_HANDLE h, const uint8_t *peeraddr, size_t peeraddr_len);
```

Sets the peer address for DTLS connections.

**Parameters:**
- `h`: Handle
- `peeraddr`: Peer address structure (e.g., `struct sockaddr`)
- `peeraddr_len`: Length of address structure

**Returns:** `1` on success, `0` on failure

---

### msspi_set_dtls_mtu

```c
int msspi_set_dtls_mtu(MSSPI_HANDLE h, size_t mtu);
```

Sets the MTU for DTLS connections.

**Parameters:**
- `h`: Handle
- `mtu`: Maximum transmission unit size

**Returns:** `1` on success, `0` on failure

---

### msspi_set_version

```c
int msspi_set_version(MSSPI_HANDLE h, int min, int max);
```

Sets the minimum and maximum protocol versions. **Call before [`msspi_set_mycert()`](#msspi_set_mycert)** as this affects credential caching.

**Parameters:**
- `h`: Handle
- `min`: Minimum version (e.g., `TLS1_2_VERSION`)
- `max`: Maximum version (or `0` for highest available)

**Returns:** `1` on success, `0` on failure

---

### msspi_set_cipherlist

```c
int msspi_set_cipherlist(MSSPI_HANDLE h, const uint8_t *cipherlist, size_t cipherlist_len);
```

Sets allowed cipher suites. **Call before [`msspi_set_mycert()`](#msspi_set_mycert)** as this affects credential caching.

**Parameters:**
- `h`: Handle
- `cipherlist`: Cipher list string
- `cipherlist_len`: Length of cipher list

**Returns:** `1` on success, `0` on failure

---

### msspi_set_hostname

```c
int msspi_set_hostname(MSSPI_HANDLE h, const uint8_t *hostname, size_t hostname_len);
```

Sets the server hostname for SNI and certificate verification. **Call before [`msspi_set_mycert()`](#msspi_set_mycert)** as this affects credential caching.

**Parameters:**
- `h`: Handle
- `hostname`: Hostname string
- `hostname_len`: Length of hostname

**Returns:** `1` on success, `0` on failure

---

### msspi_set_alpn

```c
int msspi_set_alpn(MSSPI_HANDLE h, const uint8_t *alpn, size_t alpn_len);
```

Sets ALPN (Application-Layer Protocol Negotiation) protocols.

**Parameters:**
- `h`: Handle
- `alpn`: ALPN protocol list
- `alpn_len`: Length of ALPN list

**Returns:** `1` on success, `0` on failure

---

### msspi_set_peerauth

```c
int msspi_set_peerauth(MSSPI_HANDLE h, int enable);
```

Enables or disables peer authentication. **Call before [`msspi_set_mycert()`](#msspi_set_mycert)** as this affects credential caching.

**Parameters:**
- `h`: Handle
- `enable`: `1` to require peer certificate, `0` otherwise

**Returns:** `1` on success, `0` on failure

---

### msspi_set_cert_cb

```c
int msspi_set_cert_cb(MSSPI_HANDLE h, msspi_cert_cb cert);
```

Sets a callback for dynamic certificate selection during handshake.

**Parameters:**
- `h`: Handle
- `cert`: Callback function

**Callback signature:**
```c
typedef int (*msspi_cert_cb)(void *cb_arg);
```

**Callback behavior:**
- Called during the handshake when the server requests a client certificate
- [`msspi_state()`](#msspi_state) returns `MSSPI_X509_LOOKUP` from the moment the callback is called until it returns `1`
- **Important:** Before selecting a client certificate, you must verify the server's certificate
- Typical workflow:
  1. Get peer certificate chain using [`msspi_get_peerchain()`](#msspi_get_peerchain)
  2. Verify peer certificates using [`msspi_get_verify_status()`](#msspi_get_verify_status)
  3. Get acceptable issuer list from server using [`msspi_get_issuerlist()`](#msspi_get_issuerlist) (if present)
  4. Select appropriate client certificate based on issuer list
  5. Load selected certificate using [`msspi_set_mycert()`](#msspi_set_mycert) from within the callback
  6. Return `1` to continue the handshake, `0` to abort, or `-1` to retry later

**Note:** This is primarily for client-side certificate selection. While [`msspi_add_mycert()`](#msspi_add_mycert) exists, client certificate selection typically works with a single certificate at a time.

**Returns:** `1` on success, `0` on failure

---

### msspi_set_certstore

```c
int msspi_set_certstore(MSSPI_HANDLE h, const uint8_t *store, size_t store_len);
```

Sets the Windows certificate store name to search for certificates. **Call before [`msspi_set_mycert()`](#msspi_set_mycert)**.

**Parameters:**
- `h`: Handle
- `store`: Store name (e.g., "MY", "ROOT", "CA")
- `store_len`: Length of store name

**Returns:** `1` on success, `0` on failure

---

### msspi_set_credprovider

```c
int msspi_set_credprovider(MSSPI_HANDLE h, const uint8_t *credprovider, size_t credprovider_len);
```

Sets the credential provider name. **Call before [`msspi_set_mycert()`](#msspi_set_mycert)** if needed.

**Parameters:**
- `h`: Handle
- `credprovider`: Provider name
- `credprovider_len`: Length of provider name

**Returns:** `1` on success, `0` on failure

---

### msspi_set_pin_cache

```c
int msspi_set_pin_cache(MSSPI_HANDLE h, int enable);
```

Controls PIN caching behavior for smart card certificates.

**Parameters:**
- `h`: Handle
- `enable`: `1` to cache PIN, `0` to clear cache each time

**Returns:** `1` on success, `0` on failure

---

### msspi_set_cachestring

```c
int msspi_set_cachestring(MSSPI_HANDLE h, const uint8_t *cachestring, size_t cachestring_len);
```

Sets a custom cache string for credential caching. **Call before [`msspi_set_mycert()`](#msspi_set_mycert)** as this affects credential caching.

**Parameters:**
- `h`: Handle
- `cachestring`: Custom cache identifier
- `cachestring_len`: Length of cache string

**Returns:** `1` on success, `0` on failure

---

### msspi_set_mycert

```c
int msspi_set_mycert(MSSPI_HANDLE h, const uint8_t *cert, size_t cert_len);
```

Sets the working certificate by searching for a certificate based on input data in the certificate store (defaults to "MY", configurable via [`msspi_set_certstore()`](#msspi_set_certstore)). Sets client or server certificates depending on [`msspi_set_client()`](#msspi_set_client). **Call this LAST** after all credential-affecting parameters (version, cipherlist, hostname, peerauth, cachestring).

**Supported input formats:**
- **DER format**: Binary certificate data
- **PEM/BASE64 format**: Base64-encoded certificate (with or without PEM headers)
- **SHA1 hash**: Hex string representing the certificate's SHA1 hash
- **Key Identifier**: Hex string representing the certificate's key identifier
- **Subject string**: Certificate subject name

The function first tries to parse the input as DER or PEM certificate. If that fails, it attempts to find the certificate in the Windows certificate store (configured via [`msspi_set_certstore()`](#msspi_set_certstore)) using the hash, key identifier, or subject string.

**Note:** When searching in the certificate store, only certificates with an associated private key (having the `CERT_KEY_PROV_INFO_PROP_ID` property) are accepted.

**Parameters:**
- `h`: Handle
- `cert`: Certificate data, hash, key identifier, or subject string
- `cert_len`: Length of input data

**Returns:** `1` on success, `0` on failure

---

### msspi_add_mycert

```c
int msspi_add_mycert(MSSPI_HANDLE h, const uint8_t *cert, size_t cert_len);
```

Adds an additional working certificate. Behaves the same as [`msspi_set_mycert()`](#msspi_set_mycert) but adds the certificate instead of replacing existing ones.

**Server mode behavior:** Multiple server certificates can be set using [`msspi_set_mycert()`](#msspi_set_mycert) followed by `msspi_add_mycert()`. The server processes them in the order they were added during ClientHello handling and session parameter negotiation. The first certificate that successfully matches the client's parameters will be used.

**Parameters:**
- `h`: Handle
- `cert`: Certificate data, hash, key identifier, or subject string
- `cert_len`: Length of input data

**Returns:** `1` on success, `0` on failure

---

### msspi_set_mycert_pfx

```c
int msspi_set_mycert_pfx(MSSPI_HANDLE h, const uint8_t *pfx, size_t pfx_len,
                         const uint8_t *password, size_t password_len);
```

Sets the certificate from PFX/PKCS#12 format. Works with client or server certificates depending on [`msspi_set_client()`](#msspi_set_client). **Call this LAST** after all credential-affecting parameters.

**Parameters:**
- `h`: Handle
- `pfx`: PFX/PKCS#12 data
- `pfx_len`: Length of PFX data
- `password`: Password for PFX file
- `password_len`: Length of password

**Returns:** `1` on success, `0` on failure

---

### msspi_add_mycert_pfx

```c
int msspi_add_mycert_pfx(MSSPI_HANDLE h, const uint8_t *pfx, size_t pfx_len,
                         const uint8_t *password, size_t password_len);
```

Adds an additional certificate from PFX/PKCS#12 format. Works with client or server certificates depending on [`msspi_set_client()`](#msspi_set_client). **Call this LAST** after all credential-affecting parameters.

**Server mode behavior:** When multiple server certificates are added using `msspi_add_mycert_pfx()`, the server processes them in the order they were added during ClientHello handling and session parameter negotiation. The first certificate that successfully matches the client's parameters will be used.

**Parameters:**
- `h`: Handle
- `pfx`: PFX/PKCS#12 data
- `pfx_len`: Length of PFX data
- `password`: Password for PFX file
- `password_len`: Length of password

**Returns:** `1` on success, `0` on failure

---

### msspi_set_mycert_options

```c
int msspi_set_mycert_options(MSSPI_HANDLE h, int silent, const uint8_t *pin,
                              size_t pin_len, int selftest);
```

Sets certificate options. Works with client or server certificates depending on [`msspi_set_client()`](#msspi_set_client). **Call this LAST** after setting the certificate.

**Parameters:**
- `h`: Handle
- `silent`: `1` for silent operation (no UI prompts)
- `pin`: PIN for smart card
- `pin_len`: Length of PIN
- `selftest`: `1` to perform self-test

**Returns:** `1` on success, `0` on failure

---

### msspi_set_input

```c
int msspi_set_input(MSSPI_HANDLE h, const uint8_t *input, size_t input_len);
```

Sets input data for processing. Can only be called when the input buffer is empty (`h->in_len == 0`).

**Use case:** This function is primarily intended for client mode, when using SSPI implementations that support switching to an already-sent ClientHello message from another library. It allows you to provide the ClientHello that was sent externally, so that MSSPI can continue the handshake from that point. Technically, the function works in any mode, but client mode is the primary use case.

**Parameters:**
- `h`: Handle (primarily intended for client mode)
- `input`: ClientHello message data that was already sent by another library
- `input_len`: Length of input data (must not exceed the size of the internal buffer)

**Returns:** `1` on success, `0` on failure (returns error if buffer is not empty or data exceeds buffer size)

**Note:** This is a specialized function for advanced use cases. In normal operation, data is read through the `read_cb` callback.

**Example usage:** See [Chromium-Gost implementation](https://github.com/deemru/Chromium-Gost/blob/478242ca6d1cf31963aea9794a8a442d9eb90d2d/src/gostssl.cpp#L664) for a real-world example of using this function to switch from BoringSSL to MSSPI after an external ClientHello.

---

### msspi_connect

```c
int msspi_connect(MSSPI_HANDLE h);
```

Performs TLS/DTLS handshake as client.

**Parameters:**
- `h`: Handle

**Returns:**
- `1` when handshake completes successfully
- `0` on error
- `-1` when waiting for I/O or certificate selection (use [`msspi_state()`](#msspi_state) for detailed status information)

---

### msspi_accept

```c
int msspi_accept(MSSPI_HANDLE h);
```

Performs TLS/DTLS handshake as server.

**Parameters:**
- `h`: Handle

**Returns:**
- `1` when handshake completes successfully
- `0` on error
- `-1` when waiting for I/O or certificate selection (use [`msspi_state()`](#msspi_state) for detailed status information)

---

### msspi_pending

```c
int msspi_pending(MSSPI_HANDLE h);
```

Returns the number of bytes available to read without blocking.

**Parameters:**
- `h`: Handle

**Returns:** Number of bytes available (≥0)

---

### msspi_read

```c
int msspi_read(MSSPI_HANDLE h, void *buf, int len);
```

Reads decrypted data from the connection.

**Parameters:**
- `h`: Handle
- `buf`: Buffer to receive data
- `len`: Maximum number of bytes to read

**Returns:**
- Number of bytes read (>0)
- `0` on error (check [`msspi_last_error()`](#msspi_last_error))
- `-1` when waiting for I/O

---

### msspi_peek

```c
int msspi_peek(MSSPI_HANDLE h, void *buf, int len);
```

Peeks at decrypted data without removing it from the buffer.

**Parameters:**
- `h`: Handle
- `buf`: Buffer to receive data
- `len`: Maximum number of bytes to peek

**Returns:**
- Number of bytes peeked (≥0)
- `-1` when waiting for I/O

---

### msspi_write

```c
int msspi_write(MSSPI_HANDLE h, const void *buf, int len);
```

Writes data to the connection (will be encrypted).

**Parameters:**
- `h`: Handle
- `buf`: Data to write
- `len`: Number of bytes to write

**Returns:**
- Number of bytes written (>0)
- `0` on error
- `-1` when waiting for I/O

---

### msspi_shutdown

```c
int msspi_shutdown(MSSPI_HANDLE h);
```

Performs TLS/DTLS shutdown.

**Parameters:**
- `h`: Handle

**Returns:**
- `1` on success
- `0` on error
- `-1` when waiting for I/O

---

### msspi_random

```c
int msspi_random(void *buf, int len);
```

Generates cryptographically secure random bytes.

**Parameters:**
- `buf`: Buffer to receive random data
- `len`: Number of random bytes to generate

**Returns:** `1` on success, `0` on failure

---

### msspi_state

```c
int msspi_state(MSSPI_HANDLE h);
```

Returns the current connection state as a bitmask of flags.

**Parameters:**
- `h`: Handle

**Returns:** Bitmask of `MSSPI_*` state flags

**Example usage:**
- [Chromium-Gost implementation](https://github.com/deemru/Chromium-Gost/blob/478242ca6d1cf31963aea9794a8a442d9eb90d2d/src/gostssl.cpp#L695-L736) - State handling in SSL wrapper
- [stunnel-msspi implementation](https://github.com/CryptoPro/stunnel-msspi/blob/122f94ed6449cfb50c9be8b798df8ade1015566e/src/client.c#L85-L106) - Client state management
- [Qt OpenSSL backend](https://github.com/deemru/qtbase/blob/88f428687cf8ce53ce146601f2bc8f82b5a01e96/src/network/ssl/qsslsocket_openssl.cpp#L1032-L1052) - State management example

### Connection State Flags

```c
#define MSSPI_EMPTY            0
#define MSSPI_ERROR            (1 << 30)
#define MSSPI_READING          (1 << 1)
#define MSSPI_WRITING          (1 << 2)
#define MSSPI_X509_LOOKUP      (1 << 3)
#define MSSPI_SHUTDOWN_PROC    (1 << 4)
#define MSSPI_SENT_SHUTDOWN    (1 << 5)
#define MSSPI_RECEIVED_SHUTDOWN (1 << 6)
#define MSSPI_LAST_PROC_WRITE  (1 << 7)
```

---

### msspi_last_error

```c
uint32_t msspi_last_error(void);
```

Returns the last Windows error code.

**Returns:** Error code (0 for no error)

---

### msspi_set_verify_offline

```c
int msspi_set_verify_offline(MSSPI_HANDLE h, int enable);
```

Sets offline verification mode. Affects [`msspi_get_verify_status()`](#msspi_get_verify_status) and [`msspi_get_peerchain()`](#msspi_get_peerchain) - when enabled, only cached certificates are used; when disabled, online retrieval is allowed.

**Parameters:**
- `h`: Handle
- `enable`: `1` for offline (cache-only) verification, `0` for online

**Returns:** `1` on success, `0` on failure

---

### msspi_set_verify_revocation

```c
int msspi_set_verify_revocation(MSSPI_HANDLE h, int enable);
```

Enables or disables revocation checking. Only affects [`msspi_get_verify_status()`](#msspi_get_verify_status).

**Parameters:**
- `h`: Handle
- `enable`: `1` to check revocation, `0` to skip

**Returns:** `1` on success, `0` on failure

---

### msspi_get_cipherinfo

```c
int msspi_get_cipherinfo(MSSPI_HANDLE h, const SecPkgContext_CipherInfo **cipherinfo);
```

Gets cipher information for the current connection.

**Parameters:**
- `h`: Handle
- `cipherinfo`: Pointer to receive cipher info structure

**Returns:** `1` on success, `0` on failure

---

### msspi_get_version

```c
int msspi_get_version(MSSPI_HANDLE h, uint32_t *version_num,
                      const uint8_t **version_str, size_t *version_str_len);
```

Gets the negotiated protocol version.

**Parameters:**
- `h`: Handle
- `version_num`: Pointer to receive version number (e.g., `TLS1_2_VERSION`)
- `version_str`: Pointer to receive version string
- `version_str_len`: Pointer to receive string length

**Returns:** `1` on success, `0` on failure

---

### msspi_get_mycert

```c
int msspi_get_mycert(MSSPI_HANDLE h, const uint8_t **cert, size_t *cert_len);
```

Gets the local certificate.

**Parameters:**
- `h`: Handle
- `cert`: Pointer to receive certificate data
- `cert_len`: Pointer to receive certificate length

**Returns:** `1` on success, `0` on failure

---

### msspi_get_peercerts

```c
int msspi_get_peercerts(MSSPI_HANDLE h, const uint8_t **certs,
                        size_t *certs_lens, size_t *certs_count);
```

Gets peer certificates from the connection.

**Parameters:**
- `h`: Handle
- `certs`: Pointer to receive array of certificate pointers
- `certs_lens`: Pointer to receive array of certificate lengths
- `certs_count`: Pointer to certificate count (input: array size, output: actual count)

**Returns:** `1` on success, `0` on failure

---

### msspi_get_peerchain

```c
int msspi_get_peerchain(MSSPI_HANDLE h, const uint8_t **certs,
                        size_t *certs_lens, size_t *certs_count);
```

Gets the complete peer certificate chain. The chain building behavior is controlled by [`msspi_set_verify_offline()`](#msspi_set_verify_offline) - if offline mode is enabled, only cached certificates are used; otherwise, online retrieval is allowed.

**Parameters:**
- `h`: Handle
- `certs`: Pointer to receive array of certificate pointers
- `certs_lens`: Pointer to receive array of certificate lengths
- `certs_count`: Pointer to certificate count (input: array size, output: actual count)

**Returns:** `1` on success, `0` on failure

---

### msspi_get_peernames

```c
int msspi_get_peernames(MSSPI_HANDLE h, const uint8_t **subject, size_t *subject_len,
                        const uint8_t **issuer, size_t *issuer_len);
```

Gets peer certificate subject and issuer names.

**Parameters:**
- `h`: Handle
- `subject`: Pointer to receive subject name
- `subject_len`: Pointer to receive subject name length
- `issuer`: Pointer to receive issuer name
- `issuer_len`: Pointer to receive issuer name length

**Returns:** `1` on success, `0` on failure

---

### msspi_get_issuerlist

```c
int msspi_get_issuerlist(MSSPI_HANDLE h, const uint8_t **certs,
                         size_t *certs_lens, size_t *certs_count);
```

Gets the list of acceptable certificate issuers from the server.

**Parameters:**
- `h`: Handle
- `certs`: Pointer to receive array of certificate pointers
- `certs_lens`: Pointer to receive array of certificate lengths
- `certs_count`: Pointer to certificate count (input: array size, output: actual count)

**Returns:** `1` on success, `0` on failure

---

### msspi_get_alpn

```c
int msspi_get_alpn(MSSPI_HANDLE h, const uint8_t **alpn, size_t *alpn_len);
```

Gets the negotiated ALPN protocol.

**Parameters:**
- `h`: Handle
- `alpn`: Pointer to receive ALPN string
- `alpn_len`: Pointer to receive ALPN length

**Returns:** `1` on success, `0` on failure

---

### msspi_get_verify_status

```c
int msspi_get_verify_status(MSSPI_HANDLE h, uint32_t *status);
```

Verifies the peer certificate.

**Parameters:**
- `h`: Handle
- `status`: Pointer to receive verification result (`ERROR_SUCCESS` or error code)

**Returns:** `1` on success (check `status`), `0` on failure

### Certificate Verification Error Codes

```c
#define TRUST_E_CERT_SIGNATURE       0x80096004L
#define CRYPT_E_REVOKED              0x80092010L
#define CERT_E_UNTRUSTEDROOT         0x800B0109L
#define CERT_E_UNTRUSTEDTESTROOT     0x800B010DL
#define CERT_E_CHAINING              0x800B010AL
#define CERT_E_REVOCATION_FAILURE    0x800B010EL
#define CERT_E_WRONG_USAGE           0x800B0110L
#define CERT_E_EXPIRED               0x800B0101L
#define CERT_E_INVALID_NAME          0x800B0114L
#define CERT_E_CN_NO_MATCH           0x800B010FL
#define CERT_E_INVALID_POLICY        0x800B0113L
#define TRUST_E_BASIC_CONSTRAINTS    0x80096019L
#define CERT_E_CRITICAL              0x800B0105L
#define CERT_E_VALIDITYPERIODNESTING 0x800B0102L
#define CRYPT_E_NO_REVOCATION_CHECK  0x80092012L
#define CRYPT_E_REVOCATION_OFFLINE   0x80092013L
#define CERT_E_ROLE                  0x800B0103L
```

---

### msspi_get_peercert_in_store_status

```c
int msspi_get_peercert_in_store_status(MSSPI_HANDLE h, const uint8_t *store, size_t store_len, uint32_t *status);
```

Checks if the peer certificate exists in a specific Windows certificate store.

**Parameters:**
- `h`: Handle
- `store`: Store name (e.g., "ROOT", "CA")
- `store_len`: Length of store name
- `status`: Pointer to receive result (`ERROR_SUCCESS` if certificate found, `ERROR_NOT_FOUND` otherwise)

**Returns:** `1` on success (check `status`), `0` on failure

---

### msspi_close

```c
int msspi_close(MSSPI_HANDLE h);
```

Closes the handle and frees all resources.

**Parameters:**
- `h`: Handle

**Returns:** `1` on success, `0` on failure

## Certificate Parsing (Optional)

When `MSSPI_USE_MSSPI_CERT` is defined, additional certificate parsing functions are available. See [MSSPI_CERT.md](MSSPI_CERT.md) for detailed documentation.
