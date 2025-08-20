# Makefile for MSSPI Examples

CC = gcc
CXX = g++
CFLAGS = -Wall -std=c99 -g -O2
CXXFLAGS = -Wall -std=c++11 -g -O2
INCLUDES = -I../src -I../third_party/cprocsp/include

# Build mode: 'full' uses real MSSPI library, 'stub' uses stub implementation
BUILD_MODE ?= stub

ifeq ($(BUILD_MODE),stub)
    LDFLAGS = -lpthread
    STUB_LIB = $(BUILD_DIR)/libmsspi_stub.a
    LIB_DEPS = $(STUB_LIB)
else
    LDFLAGS = -L../build_linux -lmsspi -lpthread -lstdc++
    LIB_DEPS = ../build_linux/libmsspi.a
endif

# Detect platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS += -ldl
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -ldl
endif

# Build directories
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

# Targets
EXAMPLE_TARGET = $(BUILD_DIR)/msspi_example

# Source files
SOURCES = msspi_example.c
STUB_SOURCES = msspi_stub.c
OBJECTS = $(SOURCES:%.c=$(OBJ_DIR)/%.o)
STUB_OBJECTS = $(STUB_SOURCES:%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean lib test stub full help

all: $(EXAMPLE_TARGET)

# Build modes
stub:
	@$(MAKE) BUILD_MODE=stub $(EXAMPLE_TARGET)

full:
	@$(MAKE) BUILD_MODE=full $(EXAMPLE_TARGET)

# Build the main library first (only for full mode)
lib:
ifeq ($(BUILD_MODE),full)
	@echo "Building MSSPI library..."
	@cd ../build_linux && $(MAKE)
else
	@echo "Using stub implementation, no external library needed"
endif

# Build stub library
$(STUB_LIB): $(STUB_OBJECTS) | $(BUILD_DIR)
	@echo "Creating stub library $@..."
	ar cr $@ $^

# Create build directories
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(OBJ_DIR): | $(BUILD_DIR)
	@mkdir -p $(OBJ_DIR)

# Compile object files
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link example executable
$(EXAMPLE_TARGET): $(OBJECTS) $(LIB_DEPS) | $(BUILD_DIR)
	@echo "Linking $@ ($(BUILD_MODE) mode)..."
ifeq ($(BUILD_MODE),stub)
	$(CC) $(OBJECTS) $(STUB_LIB) $(LDFLAGS) -o $@
else
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $@
endif
	@echo "Build complete: $@"

# Test targets
test-tls: $(EXAMPLE_TARGET)
	@echo "Testing TLS functionality..."
	@echo "Starting TLS server in background..."
	@$(EXAMPLE_TARGET) --server --tls --port 14433 & \
	SERVER_PID=$$!; \
	sleep 2; \
	echo "Running TLS client..."; \
	$(EXAMPLE_TARGET) --client --tls --host localhost --port 14433; \
	CLIENT_EXIT=$$?; \
	echo "Stopping TLS server..."; \
	kill $$SERVER_PID 2>/dev/null || true; \
	wait $$SERVER_PID 2>/dev/null || true; \
	exit $$CLIENT_EXIT

test-dtls: $(EXAMPLE_TARGET)
	@echo "Testing DTLS functionality..."
	@echo "Starting DTLS server in background..."
	@$(EXAMPLE_TARGET) --server --dtls --port 14434 & \
	SERVER_PID=$$!; \
	sleep 2; \
	echo "Running DTLS client..."; \
	$(EXAMPLE_TARGET) --client --dtls --host localhost --port 14434; \
	CLIENT_EXIT=$$?; \
	echo "Stopping DTLS server..."; \
	kill $$SERVER_PID 2>/dev/null || true; \
	wait $$SERVER_PID 2>/dev/null || true; \
	exit $$CLIENT_EXIT

test: test-tls test-dtls

# Clean build files
clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILD_DIR)

# Help target
help:
	@echo "Available targets:"
	@echo "  all       - Build the example application (default: stub mode)"
	@echo "  stub      - Build with stub implementation (for testing/demo)"
	@echo "  full      - Build with real MSSPI library (requires CryptoPro CSP)"
	@echo "  lib       - Build the MSSPI library (full mode only)"
	@echo "  test      - Run both TLS and DTLS tests"
	@echo "  test-tls  - Run TLS client/server test"
	@echo "  test-dtls - Run DTLS client/server test"
	@echo "  clean     - Clean build files"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Build modes:"
	@echo "  stub - Uses stub implementation, no external dependencies"
	@echo "  full - Uses real MSSPI library, requires CryptoPro CSP"
	@echo ""
	@echo "Examples:"
	@echo "  make BUILD_MODE=stub    # Build with stub (default)"
	@echo "  make BUILD_MODE=full    # Build with real library"
	@echo ""
	@echo "Manual usage examples:"
	@echo "  $(EXAMPLE_TARGET) --server --tls --port 4433"
	@echo "  $(EXAMPLE_TARGET) --client --tls --host localhost --port 4433"
	@echo "  $(EXAMPLE_TARGET) --server --dtls --port 4434"
	@echo "  $(EXAMPLE_TARGET) --client --dtls --host localhost --port 4434"