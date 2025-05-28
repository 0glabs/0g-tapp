# Makefile for TDX Boost

CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
LDFLAGS = -lcrypto -lssl
LIB_LDFLAGS = -shared -fPIC

# Check if TDX is available
ifneq ($(wildcard /usr/lib64/libtdx_attest.so),)
    LDFLAGS += -ltdx_attest
    CFLAGS += -DHAVE_TDX_ATTEST
endif

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BIN_DIR = bin
LIB_DIR = lib

# Source files
SRC = $(SRC_DIR)/boost.c
HEADERS = $(INCLUDE_DIR)/boost.h

# Target binary and library names
BIN_TARGET = $(BIN_DIR)/tapp-boost
LIB_TARGET = $(LIB_DIR)/libtapp-boost.so

# Installation paths
INSTALL_BIN_DIR = /usr/local/bin
INSTALL_LIB_DIR = /usr/local/lib
INSTALL_INCLUDE_DIR = /usr/local/include/tapp

.PHONY: all clean install libdir lib

all: $(BIN_DIR) $(BIN_TARGET)

lib: libdir $(LIB_TARGET)

libdir:
	mkdir -p $(LIB_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Build the executable
$(BIN_TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

# Build the shared library
$(LIB_TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) $(LIB_LDFLAGS) $(SRC) -o $@ $(LDFLAGS)

# Install targets
install: all lib
	mkdir -p $(INSTALL_BIN_DIR)
	mkdir -p $(INSTALL_LIB_DIR)
	mkdir -p $(INSTALL_INCLUDE_DIR)
	install -m 755 $(BIN_TARGET) $(INSTALL_BIN_DIR)/
	install -m 644 $(LIB_TARGET) $(INSTALL_LIB_DIR)/
	install -m 644 $(HEADERS) $(INSTALL_INCLUDE_DIR)/
	ldconfig

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) $(LIB_DIR)