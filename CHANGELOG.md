# Changelog

## 1.0.8

- Replaced fixed-size I/O buffers with dynamically sized buffers

---

## 1.0.7

- Fixed PIN handling in [`msspi_set_mycert_options()`](MSSPI.md#msspi_set_mycert_options)

---

## 1.0.6

- Added [`msspi_dtls_retransmit()`](MSSPI.md#msspi_dtls_retransmit) to request DTLS handshake retransmission
- Fixed DTLS protocol range handling in [`msspi_set_version()`](MSSPI.md#msspi_set_version)
- Improved [`msspi_connect()`](MSSPI.md#msspi_connect) and [`msspi_accept()`](MSSPI.md#msspi_accept) DTLS handshake handling for retransmits, fragmented handshake output, and graceful DTLS shutdown
- Disabled automatic certificate updates when building certificate chains
- Synced CryptoPro CSP SDK headers to the 2026 layout

---

## 1.0.5

- Improved certificate and PFX format probing via `CRYPT_STRING_ANY`
- Fixed `CHECK_HANDLE` macro for `MSSPI_CERT_HANDLE`
- Added `static-cert` build target (`libmsspi-cert.a`) to Linux Makefile

---

## 1.0.4

- Added DTLS-SRTP support: [`msspi_set_srtp_profiles()`](MSSPI.md#msspi_set_srtp_profiles), [`msspi_get_srtp_profile()`](MSSPI.md#msspi_get_srtp_profile)
- Added keying material export: [`msspi_set_keying_material_info()`](MSSPI.md#msspi_set_keying_material_info), [`msspi_get_keying_material()`](MSSPI.md#msspi_get_keying_material)
- Improved handshake loop in [`msspi_connect()`](MSSPI.md#msspi_connect) and [`msspi_accept()`](MSSPI.md#msspi_accept)

---

## 1.0.3

- Fixed broken logic regression in [`msspi_get_peerchain()`](MSSPI.md#msspi_get_peerchain)
- Safer definition of shared TLS/DTLS version constants

---

## 1.0.2

- Fixed regression in [`msspi_set_mycert()`](MSSPI.md#msspi_set_mycert) where SHA1/KeyID/Subject certificate lookup failed
- Updated documentation for [`msspi_set_mycert()`](MSSPI.md#msspi_set_mycert) and [`msspi_add_mycert()`](MSSPI.md#msspi_add_mycert)

---

## 1.0.1

- Added base documentation [MSSPI.md](MSSPI.md)
- Added certificate parsing documentation [MSSPI_CERT.md](MSSPI_CERT.md)
- Added project readme [README.md](README.md)
- Added changelog [CHANGELOG.md](CHANGELOG.md)
- Reordered functions in header file to follow logical flow
- Improved DTLS support
- Changed [`msspi_is_cipher_supported()`](MSSPI.md#msspi_is_cipher_supported) prototype to include `dtls` parameter
- Changed [`msspi_get_peerchain()`](MSSPI.md#msspi_get_peerchain) prototype, moved online/offline logic to [`msspi_set_verify_offline()`](MSSPI.md#msspi_set_verify_offline)
- Renamed `msspi_verify()` to [`msspi_get_verify_status()`](MSSPI.md#msspi_get_verify_status)
- Renamed `msspi_verify_peer_in_store()` to [`msspi_get_peercert_in_store_status()`](MSSPI.md#msspi_get_peercert_in_store_status)
- Added `CertGetSubjectCertificateFromStore()` to CAPIX

---

## 1.0.0

- Initial release
