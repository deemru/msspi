/*
 * MSSPI Stub Implementation for Testing
 * 
 * This is a minimal stub implementation of MSSPI that allows the examples
 * to compile and demonstrate API usage patterns without requiring the full
 * CryptoPro CSP environment.
 * 
 * This is NOT a real TLS/DTLS implementation - it's just for testing
 * the integration patterns and API usage.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

// Ensure we have strdup available
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
char *strdup(const char *s); // Declare strdup if not available

#include "msspi.h"

// Stub structure
struct MSSPI {
    void *cb_arg;
    msspi_read_cb read_cb;
    msspi_write_cb write_cb;
    char *hostname;
    int is_client;
    int is_dtls;
    int connected;
    char last_error[256];
};

struct MSSPI_CERT {
    char dummy;
};

// Global error code
static DWORD g_last_error = 0;

// Basic implementations
MSSPI_HANDLE msspi_open(void *cb_arg, msspi_read_cb read_cb, msspi_write_cb write_cb) {
    printf("[STUB] msspi_open called\n");
    
    if (!read_cb || !write_cb) {
        g_last_error = 1; // ERROR_INVALID_FUNCTION
        return NULL;
    }
    
    MSSPI_HANDLE h = (MSSPI_HANDLE)malloc(sizeof(struct MSSPI));
    if (!h) {
        g_last_error = 14; // ERROR_OUTOFMEMORY
        return NULL;
    }
    
    memset(h, 0, sizeof(struct MSSPI));
    h->cb_arg = cb_arg;
    h->read_cb = read_cb;
    h->write_cb = write_cb;
    h->is_client = 0; // Default to server
    h->is_dtls = 0;   // Default to TLS
    h->connected = 0;
    
    return h;
}

char msspi_set_hostname(MSSPI_HANDLE h, const char *hostname) {
    printf("[STUB] msspi_set_hostname: %s\n", hostname ? hostname : "(null)");
    
    if (!h) {
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return 0;
    }
    
    if (h->hostname) {
        free(h->hostname);
        h->hostname = NULL;
    }
    
    if (hostname) {
        h->hostname = strdup(hostname);
        if (!h->hostname) {
            g_last_error = 14; // ERROR_OUTOFMEMORY
            return 0;
        }
    }
    
    return 1;
}

void msspi_set_client(MSSPI_HANDLE h) {
    printf("[STUB] msspi_set_client called\n");
    if (h) {
        h->is_client = 1;
    }
}

void msspi_set_dtls(MSSPI_HANDLE h) {
    printf("[STUB] msspi_set_dtls called\n");
    if (h) {
        h->is_dtls = 1;
    }
}

void msspi_set_dtls_mtu(MSSPI_HANDLE h, size_t mtu) {
    printf("[STUB] msspi_set_dtls_mtu: %zu\n", mtu);
    // Stub - just log
}

void msspi_set_dtls_peeraddr(MSSPI_HANDLE h, const uint8_t *peeraddr, size_t len) {
    printf("[STUB] msspi_set_dtls_peeraddr: %zu bytes\n", len);
    // Stub - just log
}

void msspi_set_version(MSSPI_HANDLE h, int min, int max) {
    printf("[STUB] msspi_set_version: min=0x%04x, max=0x%04x\n", min, max);
    // Stub - just log
}

int msspi_connect(MSSPI_HANDLE h) {
    printf("[STUB] msspi_connect called\n");
    
    if (!h) {
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return 0;
    }
    
    if (!h->is_client) {
        printf("[STUB] msspi_connect: Error - not configured as client\n");
        g_last_error = 1; // ERROR_INVALID_FUNCTION
        return 0;
    }
    
    // Simulate handshake by sending/receiving some data
    char handshake_data[] = "CLIENT_HELLO_STUB";
    int sent = h->write_cb(h->cb_arg, handshake_data, strlen(handshake_data));
    if (sent < 0) {
        printf("[STUB] msspi_connect: Failed to send handshake data\n");
        g_last_error = 2; // ERROR_FILE_NOT_FOUND (generic I/O error)
        return sent;
    }
    
    char response[256];
    int received = h->read_cb(h->cb_arg, response, sizeof(response) - 1);
    if (received < 0) {
        printf("[STUB] msspi_connect: Failed to receive handshake response\n");
        g_last_error = 2; // ERROR_FILE_NOT_FOUND (generic I/O error)
        return received;
    }
    
    response[received] = '\0';
    printf("[STUB] msspi_connect: Received handshake response: %s\n", response);
    
    h->connected = 1;
    printf("[STUB] msspi_connect: Handshake successful\n");
    return 1;
}

int msspi_accept(MSSPI_HANDLE h) {
    printf("[STUB] msspi_accept called\n");
    
    if (!h) {
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return 0;
    }
    
    if (h->is_client) {
        printf("[STUB] msspi_accept: Error - configured as client\n");
        g_last_error = 1; // ERROR_INVALID_FUNCTION
        return 0;
    }
    
    // Simulate handshake by receiving/sending some data
    char handshake_data[256];
    int received = h->read_cb(h->cb_arg, handshake_data, sizeof(handshake_data) - 1);
    if (received < 0) {
        printf("[STUB] msspi_accept: Failed to receive handshake data\n");
        g_last_error = 2; // ERROR_FILE_NOT_FOUND (generic I/O error)
        return received;
    }
    
    handshake_data[received] = '\0';
    printf("[STUB] msspi_accept: Received handshake data: %s\n", handshake_data);
    
    char response[] = "SERVER_HELLO_STUB";
    int sent = h->write_cb(h->cb_arg, response, strlen(response));
    if (sent < 0) {
        printf("[STUB] msspi_accept: Failed to send handshake response\n");
        g_last_error = 2; // ERROR_FILE_NOT_FOUND (generic I/O error)
        return sent;
    }
    
    h->connected = 1;
    printf("[STUB] msspi_accept: Handshake successful\n");
    return 1;
}

int msspi_read(MSSPI_HANDLE h, void *buf, int len) {
    if (!h) {
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return -1;
    }
    
    if (!h->connected) {
        g_last_error = 1; // ERROR_INVALID_FUNCTION
        return -1;
    }
    
    // In stub mode, just pass through to the socket
    int result = h->read_cb(h->cb_arg, buf, len);
    if (result > 0) {
        printf("[STUB] msspi_read: %d bytes\n", result);
    }
    return result;
}

int msspi_write(MSSPI_HANDLE h, const void *buf, int len) {
    if (!h) {
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return -1;
    }
    
    if (!h->connected) {
        g_last_error = 1; // ERROR_INVALID_FUNCTION
        return -1;
    }
    
    // In stub mode, just pass through to the socket
    int result = h->write_cb(h->cb_arg, buf, len);
    if (result > 0) {
        printf("[STUB] msspi_write: %d bytes\n", result);
    }
    return result;
}

int msspi_shutdown(MSSPI_HANDLE h) {
    printf("[STUB] msspi_shutdown called\n");
    
    if (!h) {
        g_last_error = 6; // ERROR_INVALID_HANDLE
        return 0;
    }
    
    h->connected = 0;
    return 1;
}

void msspi_close(MSSPI_HANDLE h) {
    printf("[STUB] msspi_close called\n");
    
    if (!h) {
        return;
    }
    
    if (h->hostname) {
        free(h->hostname);
    }
    
    free(h);
}

const char *msspi_get_version(MSSPI_HANDLE h) {
    printf("[STUB] msspi_get_version called\n");
    
    if (!h) {
        return "Unknown";
    }
    
    return h->is_dtls ? "DTLSv1.2-STUB" : "TLSv1.2-STUB";
}

DWORD msspi_last_error(void) {
    return g_last_error;
}

// Minimal stubs for other functions that might be called
char msspi_set_cachestring(MSSPI_HANDLE h, const char *cacheString) {
    printf("[STUB] msspi_set_cachestring: %s\n", cacheString ? cacheString : "(null)");
    return 1;
}

char msspi_set_alpn(MSSPI_HANDLE h, const char *alpn, size_t len) {
    printf("[STUB] msspi_set_alpn: %zu bytes\n", len);
    return 1;
}

void msspi_set_certstore(MSSPI_HANDLE h, const char *store) {
    printf("[STUB] msspi_set_certstore: %s\n", store ? store : "(null)");
}

char msspi_set_mycert(MSSPI_HANDLE h, const char *clientCert, int len) {
    printf("[STUB] msspi_set_mycert: %d bytes\n", len);
    return 1;
}

char msspi_add_mycert(MSSPI_HANDLE h, const char *clientCert, int len) {
    printf("[STUB] msspi_add_mycert: %d bytes\n", len);
    return 1;
}

char msspi_set_mycert_pfx(MSSPI_HANDLE h, const char *pfx, int len, const char *password) {
    printf("[STUB] msspi_set_mycert_pfx: %d bytes\n", len);
    return 1;
}

char msspi_add_mycert_pfx(MSSPI_HANDLE h, const char *pfx, int len, const char *password) {
    printf("[STUB] msspi_add_mycert_pfx: %d bytes\n", len);
    return 1;
}

char msspi_set_mycert_options(MSSPI_HANDLE h, char silent, const char *pin, char selftest) {
    printf("[STUB] msspi_set_mycert_options called\n");
    return 1;
}

void msspi_set_peerauth(MSSPI_HANDLE h, char is_peerauth) {
    printf("[STUB] msspi_set_peerauth: %d\n", is_peerauth);
}

void msspi_set_cert_cb(MSSPI_HANDLE h, msspi_cert_cb cb) {
    printf("[STUB] msspi_set_cert_cb called\n");
}

void msspi_set_pin_cache(MSSPI_HANDLE h) {
    printf("[STUB] msspi_set_pin_cache called\n");
}

char msspi_set_cipherlist(MSSPI_HANDLE h, const char *cipherlist) {
    printf("[STUB] msspi_set_cipherlist: %s\n", cipherlist ? cipherlist : "(null)");
    return 1;
}

char msspi_set_credprovider(MSSPI_HANDLE h, const char *credprovider) {
    printf("[STUB] msspi_set_credprovider: %s\n", credprovider ? credprovider : "(null)");
    return 1;
}

char msspi_set_input(MSSPI_HANDLE h, const void *buf, int len) {
    printf("[STUB] msspi_set_input: %d bytes\n", len);
    return 1;
}

void msspi_set_verify_offline(MSSPI_HANDLE h, char offline) {
    printf("[STUB] msspi_set_verify_offline: %d\n", offline);
}

void msspi_set_verify_revocation(MSSPI_HANDLE h, char revocation) {
    printf("[STUB] msspi_set_verify_revocation: %d\n", revocation);
}

char msspi_random(void *buf, int len, char safe) {
    printf("[STUB] msspi_random: %d bytes\n", len);
    // Fill with simple pseudo-random data
    unsigned char *p = (unsigned char*)buf;
    for (int i = 0; i < len; i++) {
        p[i] = (unsigned char)(rand() % 256);
    }
    return 1;
}

char msspi_is_version_supported(int version) {
    printf("[STUB] msspi_is_version_supported: 0x%04x\n", version);
    return 1; // Claim all versions are supported in stub
}

char msspi_is_cipher_supported(int cipher) {
    printf("[STUB] msspi_is_cipher_supported: %d\n", cipher);
    return 1; // Claim all ciphers are supported in stub
}

int msspi_state(MSSPI_HANDLE h) {
    if (!h) return MSSPI_ERROR;
    return h->connected ? MSSPI_OK : MSSPI_ERROR;
}

int msspi_pending(MSSPI_HANDLE h) {
    printf("[STUB] msspi_pending called\n");
    return 0; // No pending data in stub
}

int msspi_peek(MSSPI_HANDLE h, void *buf, int len) {
    printf("[STUB] msspi_peek: %d bytes\n", len);
    return 0; // No data to peek in stub
}

// Certificate functions (minimal stubs)
PSecPkgContext_CipherInfo msspi_get_cipherinfo(MSSPI_HANDLE h) {
    printf("[STUB] msspi_get_cipherinfo called\n");
    return NULL;
}

char msspi_get_mycert(MSSPI_HANDLE h, const char **buf, int *len) {
    printf("[STUB] msspi_get_mycert called\n");
    return 0;
}

char msspi_get_peercerts(MSSPI_HANDLE h, const char **bufs, int *lens, size_t *count) {
    printf("[STUB] msspi_get_peercerts called\n");
    return 0;
}

char msspi_get_peerchain(MSSPI_HANDLE h, char online, const char **bufs, int *lens, size_t *count) {
    printf("[STUB] msspi_get_peerchain called\n");
    return 0;
}

char msspi_get_peernames(MSSPI_HANDLE h, const char **subject, size_t *slen, const char **issuer, size_t *ilen) {
    printf("[STUB] msspi_get_peernames called\n");
    return 0;
}

char msspi_get_issuerlist(MSSPI_HANDLE h, const char **bufs, int *lens, size_t *count) {
    printf("[STUB] msspi_get_issuerlist called\n");
    return 0;
}

const char *msspi_get_alpn(MSSPI_HANDLE h) {
    printf("[STUB] msspi_get_alpn called\n");
    return NULL;
}

int32_t msspi_verify(MSSPI_HANDLE h) {
    printf("[STUB] msspi_verify called\n");
    return MSSPI_VERIFY_OK;
}

char msspi_verifypeer(MSSPI_HANDLE h, const char *store) {
    printf("[STUB] msspi_verifypeer: %s\n", store ? store : "(null)");
    return 1;
}

// Certificate API stubs
MSSPI_CERT_HANDLE msspi_cert_open(const char *cert, size_t len) {
    printf("[STUB] msspi_cert_open: %zu bytes\n", len);
    return (MSSPI_CERT_HANDLE)malloc(sizeof(struct MSSPI_CERT));
}

MSSPI_CERT_HANDLE msspi_cert_next(MSSPI_CERT_HANDLE h) {
    printf("[STUB] msspi_cert_next called\n");
    return NULL; // No next certificate in stub
}

char msspi_cert_subject(MSSPI_CERT_HANDLE ch, const char **buf, size_t *len, char quotes) {
    printf("[STUB] msspi_cert_subject called\n");
    return 0;
}

char msspi_cert_issuer(MSSPI_CERT_HANDLE ch, const char **buf, size_t *len, char quotes) {
    printf("[STUB] msspi_cert_issuer called\n");
    return 0;
}

char msspi_cert_serial(MSSPI_CERT_HANDLE ch, const char **buf, size_t *len) {
    printf("[STUB] msspi_cert_serial called\n");
    return 0;
}

char msspi_cert_keyid(MSSPI_CERT_HANDLE ch, const char **buf, size_t *len) {
    printf("[STUB] msspi_cert_keyid called\n");
    return 0;
}

char msspi_cert_sha1(MSSPI_CERT_HANDLE ch, const char **buf, size_t *len) {
    printf("[STUB] msspi_cert_sha1 called\n");
    return 0;
}

char msspi_cert_alg_sig(MSSPI_CERT_HANDLE ch, const char **buf, size_t *len) {
    printf("[STUB] msspi_cert_alg_sig called\n");
    return 0;
}

char msspi_cert_alg_key(MSSPI_CERT_HANDLE ch, const char **buf, size_t *len) {
    printf("[STUB] msspi_cert_alg_key called\n");
    return 0;
}

char msspi_cert_time_issued(MSSPI_CERT_HANDLE ch, struct tm *time) {
    printf("[STUB] msspi_cert_time_issued called\n");
    (void)time; // Suppress unused parameter warning
    return 0;
}

char msspi_cert_time_expired(MSSPI_CERT_HANDLE ch, struct tm *time) {
    printf("[STUB] msspi_cert_time_expired called\n");
    (void)time; // Suppress unused parameter warning
    return 0;
}

void msspi_cert_close(MSSPI_CERT_HANDLE ch) {
    printf("[STUB] msspi_cert_close called\n");
    if (ch) {
        free(ch);
    }
}