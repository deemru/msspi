/*
 * MSSPI TLS/DTLS Example Application
 * 
 * This application demonstrates both TLS and DTLS client/server functionality
 * using the MSSPI library. It can work in the following modes:
 * 
 * TLS Server:   ./example --server --tls --port 4433
 * TLS Client:   ./example --client --tls --host localhost --port 4433
 * DTLS Server:  ./example --server --dtls --port 4434
 * DTLS Client:  ./example --client --dtls --host localhost --port 4434
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../src/msspi.h"

#define DEFAULT_TLS_PORT  4433
#define DEFAULT_DTLS_PORT 4434
#define DEFAULT_HOST     "localhost"
#define MAX_BUFFER_SIZE  8192
#define DEFAULT_MESSAGE  "Hello from MSSPI example!"

typedef struct {
    int is_client;
    int is_dtls;
    char *hostname;
    int port;
    int verbose;
    int socket_fd;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len;
} app_context_t;

static volatile int g_running = 1;

// Signal handler to allow graceful shutdown
static void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    g_running = 0;
}

// Socket read callback for MSSPI
static int socket_read_cb(void *cb_arg, void *buf, int len) {
    app_context_t *ctx = (app_context_t *)cb_arg;
    int result;
    
    if (ctx->is_dtls) {
        // For DTLS, use recvfrom to get datagram
        result = recvfrom(ctx->socket_fd, buf, len, 0, 
                         (struct sockaddr *)&ctx->peer_addr, &ctx->peer_addr_len);
    } else {
        // For TLS, use regular recv
        result = recv(ctx->socket_fd, buf, len, 0);
    }
    
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1; // Would block, try again later
        }
        perror("socket read error");
        return -1;
    }
    
    if (ctx->verbose && result > 0) {
        printf("Read %d bytes from socket\n", result);
    }
    
    return result;
}

// Socket write callback for MSSPI
static int socket_write_cb(void *cb_arg, const void *buf, int len) {
    app_context_t *ctx = (app_context_t *)cb_arg;
    int result;
    
    if (ctx->is_dtls) {
        // For DTLS, use sendto to send datagram
        result = sendto(ctx->socket_fd, buf, len, 0,
                       (struct sockaddr *)&ctx->peer_addr, ctx->peer_addr_len);
    } else {
        // For TLS, use regular send
        result = send(ctx->socket_fd, buf, len, 0);
    }
    
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1; // Would block, try again later
        }
        perror("socket write error");
        return -1;
    }
    
    if (ctx->verbose && result > 0) {
        printf("Wrote %d bytes to socket\n", result);
    }
    
    return result;
}

// Create and configure socket
static int create_socket(app_context_t *ctx) {
    int sock_fd;
    int opt = 1;
    
    // Create socket
    sock_fd = socket(AF_INET, ctx->is_dtls ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket creation failed");
        return -1;
    }
    
    // Set socket options
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(sock_fd);
        return -1;
    }
    
    return sock_fd;
}

// Initialize server
static int init_server(app_context_t *ctx) {
    struct sockaddr_in server_addr;
    
    ctx->socket_fd = create_socket(ctx);
    if (ctx->socket_fd < 0) {
        return -1;
    }
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(ctx->port);
    
    // Bind socket
    if (bind(ctx->socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(ctx->socket_fd);
        return -1;
    }
    
    // For TCP, start listening
    if (!ctx->is_dtls) {
        if (listen(ctx->socket_fd, 5) < 0) {
            perror("listen failed");
            close(ctx->socket_fd);
            return -1;
        }
    }
    
    printf("Server listening on port %d (%s)\n", ctx->port, ctx->is_dtls ? "DTLS" : "TLS");
    return 0;
}

// Initialize client
static int init_client(app_context_t *ctx) {
    struct hostent *host_entry;
    
    ctx->socket_fd = create_socket(ctx);
    if (ctx->socket_fd < 0) {
        return -1;
    }
    
    // Resolve hostname
    host_entry = gethostbyname(ctx->hostname);
    if (!host_entry) {
        fprintf(stderr, "Failed to resolve hostname: %s\n", ctx->hostname);
        close(ctx->socket_fd);
        return -1;
    }
    
    // Setup server address
    memset(&ctx->peer_addr, 0, sizeof(ctx->peer_addr));
    ctx->peer_addr.sin_family = AF_INET;
    ctx->peer_addr.sin_port = htons(ctx->port);
    memcpy(&ctx->peer_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    ctx->peer_addr_len = sizeof(ctx->peer_addr);
    
    // For TCP, connect to server
    if (!ctx->is_dtls) {
        if (connect(ctx->socket_fd, (struct sockaddr *)&ctx->peer_addr, ctx->peer_addr_len) < 0) {
            perror("connect failed");
            close(ctx->socket_fd);
            return -1;
        }
    }
    
    printf("Client connecting to %s:%d (%s)\n", ctx->hostname, ctx->port, ctx->is_dtls ? "DTLS" : "TLS");
    return 0;
}

// Run server
static int run_server(app_context_t *ctx) {
    MSSPI_HANDLE msspi_handle;
    int client_fd = ctx->socket_fd;
    app_context_t client_ctx = *ctx;
    
    // For TCP, accept connection
    if (!ctx->is_dtls) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        printf("Waiting for client connection...\n");
        client_fd = accept(ctx->socket_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            perror("accept failed");
            return -1;
        }
        
        client_ctx.socket_fd = client_fd;
        client_ctx.peer_addr = client_addr;
        client_ctx.peer_addr_len = client_addr_len;
        
        printf("Client connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    }
    
    // Initialize MSSPI
    msspi_handle = msspi_open(&client_ctx, socket_read_cb, socket_write_cb);
    if (!msspi_handle) {
        fprintf(stderr, "Failed to create MSSPI handle\n");
        if (!ctx->is_dtls) close(client_fd);
        return -1;
    }
    
    // Configure MSSPI
    if (ctx->is_dtls) {
        msspi_set_dtls(msspi_handle);
        msspi_set_dtls_mtu(msspi_handle, 1400);
    }
    msspi_set_version(msspi_handle, TLS1_2_VERSION, TLS1_3_VERSION);
    
    // Perform handshake (server side)
    printf("Starting %s handshake...\n", ctx->is_dtls ? "DTLS" : "TLS");
    int result = msspi_accept(msspi_handle);
    if (result != 1) {
        fprintf(stderr, "Handshake failed: %d\n", result);
        msspi_close(msspi_handle);
        if (!ctx->is_dtls) close(client_fd);
        return -1;
    }
    
    printf("Handshake successful! Using %s\n", msspi_get_version(msspi_handle));
    
    // Echo server loop
    char buffer[MAX_BUFFER_SIZE];
    while (g_running) {
        int bytes_read = msspi_read(msspi_handle, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            printf("Received: %s\n", buffer);
            
            // Echo back
            char echo_buffer[MAX_BUFFER_SIZE];
            snprintf(echo_buffer, sizeof(echo_buffer), "Echo: %.*s", bytes_read, buffer);
            int bytes_written = msspi_write(msspi_handle, echo_buffer, strlen(echo_buffer));
            if (bytes_written < 0) {
                fprintf(stderr, "Write failed\n");
                break;
            }
        } else if (bytes_read == 0) {
            printf("Client disconnected\n");
            break;
        } else {
            // Error or would block
            usleep(10000); // 10ms
        }
    }
    
    // Cleanup
    msspi_shutdown(msspi_handle);
    msspi_close(msspi_handle);
    if (!ctx->is_dtls) close(client_fd);
    
    return 0;
}

// Run client
static int run_client(app_context_t *ctx) {
    MSSPI_HANDLE msspi_handle;
    
    // Initialize MSSPI
    msspi_handle = msspi_open(ctx, socket_read_cb, socket_write_cb);
    if (!msspi_handle) {
        fprintf(stderr, "Failed to create MSSPI handle\n");
        return -1;
    }
    
    // Configure MSSPI
    msspi_set_client(msspi_handle);
    if (ctx->is_dtls) {
        msspi_set_dtls(msspi_handle);
        msspi_set_dtls_mtu(msspi_handle, 1400);
        // Set peer address for DTLS
        msspi_set_dtls_peeraddr(msspi_handle, (uint8_t*)&ctx->peer_addr, ctx->peer_addr_len);
    }
    msspi_set_hostname(msspi_handle, ctx->hostname);
    msspi_set_version(msspi_handle, TLS1_2_VERSION, TLS1_3_VERSION);
    
    // Perform handshake (client side)
    printf("Starting %s handshake...\n", ctx->is_dtls ? "DTLS" : "TLS");
    int result = msspi_connect(msspi_handle);
    if (result != 1) {
        fprintf(stderr, "Handshake failed: %d\n", result);
        msspi_close(msspi_handle);
        return -1;
    }
    
    printf("Handshake successful! Using %s\n", msspi_get_version(msspi_handle));
    
    // Send test message
    const char *message = DEFAULT_MESSAGE;
    printf("Sending: %s\n", message);
    int bytes_written = msspi_write(msspi_handle, message, strlen(message));
    if (bytes_written < 0) {
        fprintf(stderr, "Write failed\n");
        msspi_close(msspi_handle);
        return -1;
    }
    
    // Read response
    char buffer[MAX_BUFFER_SIZE];
    int bytes_read = msspi_read(msspi_handle, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("Received: %s\n", buffer);
    } else {
        fprintf(stderr, "Read failed or no response\n");
    }
    
    // Cleanup
    msspi_shutdown(msspi_handle);
    msspi_close(msspi_handle);
    
    return 0;
}

// Print usage information
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nOPTIONS:\n");
    printf("  --server              Run as server (default: client)\n");
    printf("  --client              Run as client\n");
    printf("  --tls                 Use TLS protocol (default)\n");
    printf("  --dtls                Use DTLS protocol\n");
    printf("  --host HOST           Server hostname for client (default: %s)\n", DEFAULT_HOST);
    printf("  --port PORT           Port number (default: %d for TLS, %d for DTLS)\n", 
           DEFAULT_TLS_PORT, DEFAULT_DTLS_PORT);
    printf("  --verbose             Enable verbose output\n");
    printf("  --help                Show this help message\n");
    printf("\nEXAMPLES:\n");
    printf("  %s --server --tls --port 4433\n", program_name);
    printf("  %s --client --tls --host localhost --port 4433\n", program_name);
    printf("  %s --server --dtls --port 4434\n", program_name);
    printf("  %s --client --dtls --host localhost --port 4434\n", program_name);
}

int main(int argc, char *argv[]) {
    app_context_t ctx = {
        .is_client = 1,     // Default to client
        .is_dtls = 0,       // Default to TLS
        .hostname = DEFAULT_HOST,
        .port = 0,          // Will be set based on protocol
        .verbose = 0,
        .socket_fd = -1,
        .peer_addr_len = 0
    };
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0) {
            ctx.is_client = 0;
        } else if (strcmp(argv[i], "--client") == 0) {
            ctx.is_client = 1;
        } else if (strcmp(argv[i], "--tls") == 0) {
            ctx.is_dtls = 0;
        } else if (strcmp(argv[i], "--dtls") == 0) {
            ctx.is_dtls = 1;
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            ctx.hostname = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            ctx.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            ctx.verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Set default port if not specified
    if (ctx.port == 0) {
        ctx.port = ctx.is_dtls ? DEFAULT_DTLS_PORT : DEFAULT_TLS_PORT;
    }
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("MSSPI %s %s Example\n", 
           ctx.is_dtls ? "DTLS" : "TLS",
           ctx.is_client ? "Client" : "Server");
    
    int result = -1;
    
    if (ctx.is_client) {
        if (init_client(&ctx) == 0) {
            result = run_client(&ctx);
        }
    } else {
        if (init_server(&ctx) == 0) {
            result = run_server(&ctx);
        }
    }
    
    // Cleanup
    if (ctx.socket_fd >= 0) {
        close(ctx.socket_fd);
    }
    
    return result == 0 ? 0 : 1;
}