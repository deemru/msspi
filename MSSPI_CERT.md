# MSSPI Certificate Parsing API

## Overview

When `MSSPI_USE_MSSPI_CERT` is defined, additional certificate parsing functions are available for extracting information from X.509 certificates.

## Handle Management

### msspi_cert_open

```c
MSSPI_CERT_HANDLE msspi_cert_open(const uint8_t *cert, size_t cert_len);
```

Creates a certificate handle from certificate data in PEM or DER format.

**Parameters:**
- `cert`: Certificate data (PEM or DER)
- `cert_len`: Length of certificate data

**Returns:**
- Valid handle on success
- `NULL` on failure

---

### msspi_cert_close

```c
int msspi_cert_close(MSSPI_CERT_HANDLE ch);
```

Closes and frees a certificate handle.

**Parameters:**
- `ch`: Certificate handle

**Returns:**
- `1` on success
- `0` on failure

---

### msspi_cert_next

```c
MSSPI_CERT_HANDLE msspi_cert_next(MSSPI_CERT_HANDLE ch);
```

Retrieves the next certificate in the chain (issuer certificate).

**Parameters:**
- `ch`: Certificate handle

**Returns:**
- Handle to next certificate in chain
- `NULL` if no more certificates or on error

---

## Certificate Information

### msspi_cert_subject

```c
int msspi_cert_subject(MSSPI_CERT_HANDLE ch, const uint8_t **data, size_t *data_len, int quotes);
```

Retrieves the subject name from the certificate.

**Parameters:**
- `ch`: Certificate handle
- `data`: Pointer to receive subject name string pointer
- `data_len`: Pointer to receive subject name length
- `quotes`: `1` to include quotes around RDN values, `0` for raw values

**Returns:**
- `1` on success
- `0` on failure

---

### msspi_cert_issuer

```c
int msspi_cert_issuer(MSSPI_CERT_HANDLE ch, const uint8_t **data, size_t *data_len, int quotes);
```

Retrieves the issuer name from the certificate.

**Parameters:**
- `ch`: Certificate handle
- `data`: Pointer to receive issuer name string pointer
- `data_len`: Pointer to receive issuer name length
- `quotes`: `1` to include quotes around RDN values, `0` for raw values

**Returns:**
- `1` on success
- `0` on failure

---

### msspi_cert_serial

```c
int msspi_cert_serial(MSSPI_CERT_HANDLE ch, const uint8_t **data, size_t *data_len);
```

Retrieves the serial number from the certificate.

**Parameters:**
- `ch`: Certificate handle
- `data`: Pointer to receive serial number string pointer
- `data_len`: Pointer to receive serial number length

**Returns:**
- `1` on success
- `0` on failure

**Note:** Serial number is returned as a hexadecimal string.

---

### msspi_cert_keyid

```c
int msspi_cert_keyid(MSSPI_CERT_HANDLE ch, const uint8_t **data, size_t *data_len);
```

Retrieves the subject key identifier from the certificate.

**Parameters:**
- `ch`: Certificate handle
- `data`: Pointer to receive key identifier string pointer
- `data_len`: Pointer to receive key identifier length

**Returns:**
- `1` on success
- `0` on failure

**Note:** Key identifier is returned as a hexadecimal string.

---

### msspi_cert_sha1

```c
int msspi_cert_sha1(MSSPI_CERT_HANDLE ch, const uint8_t **data, size_t *data_len);
```

Retrieves the SHA-1 fingerprint of the certificate.

**Parameters:**
- `ch`: Certificate handle
- `data`: Pointer to receive fingerprint string pointer
- `data_len`: Pointer to receive fingerprint length

**Returns:**
- `1` on success
- `0` on failure

**Note:** Fingerprint is returned as a hexadecimal string.

---

### msspi_cert_alg_sig

```c
int msspi_cert_alg_sig(MSSPI_CERT_HANDLE ch, const uint8_t **data, size_t *data_len);
```

Retrieves the signature algorithm used in the certificate.

**Parameters:**
- `ch`: Certificate handle
- `data`: Pointer to receive algorithm string pointer
- `data_len`: Pointer to receive algorithm string length

**Returns:**
- `1` on success
- `0` on failure

---

### msspi_cert_alg_key

```c
int msspi_cert_alg_key(MSSPI_CERT_HANDLE ch, const uint8_t **data, size_t *data_len);
```

Retrieves the public key algorithm and key size.

**Parameters:**
- `ch`: Certificate handle
- `data`: Pointer to receive algorithm string pointer
- `data_len`: Pointer to receive algorithm string length

**Returns:**
- `1` on success
- `0` on failure

**Note:** Returns algorithm name and key size (e.g., "RSA (2048 бит)").

---

## Certificate Validity

### msspi_cert_time_issued

```c
int msspi_cert_time_issued(MSSPI_CERT_HANDLE ch, struct tm *time);
```

Retrieves the certificate's issue time.

**Parameters:**
- `ch`: Certificate handle
- `time`: Pointer to `struct tm` to receive the time

**Returns:**
- `1` on success
- `0` on failure

---

### msspi_cert_time_expired

```c
int msspi_cert_time_expired(MSSPI_CERT_HANDLE ch, struct tm *time);
```

Retrieves the certificate's expiration time.

**Parameters:**
- `ch`: Certificate handle
- `time`: Pointer to `struct tm` to receive the time

**Returns:**
- `1` on success
- `0` on failure

---

## String Encoding

All certificate information functions return string data in **UTF-8 encoding**:
- Certificate names (subject, issuer) are converted from Unicode to UTF-8
- Hexadecimal strings (serial number, key identifier, SHA-1 fingerprint) use ASCII characters
- Algorithm names are converted from Unicode to UTF-8

---

## Error Handling

All functions that return `int` use the following convention:
- Non-zero (`1`): Success
- Zero (`0`): Failure

On failure, call `msspi_last_error()` to get the Windows error code.

---

## Thread Safety

The certificate parsing functions are not thread-safe. Each handle should be used by a single thread.

---

## Memory Management

- Certificate handles must be closed with `msspi_cert_close()` to free resources
- Pointers returned by getter functions are valid until the handle is closed
- The library manages all internal memory allocations
