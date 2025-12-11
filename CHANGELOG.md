# Changelog

## 1.0.3

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
