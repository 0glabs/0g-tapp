CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
LDFLAGS = -lcrypto -lssl

ifneq ($(wildcard /usr/lib64/libtdx_attest.so),)
    LDFLAGS += -ltdx_attest
    CFLAGS += -DHAVE_TDX_ATTEST
endif

SRC_DIR = src
INCLUDE_DIR = include
BIN_DIR = bin
LIB_DIR = lib

SRC = $(SRC_DIR)/key_tool.c
HEADERS = $(INCLUDE_DIR)/key_tool.h

TARGET = $(BIN_DIR)/key-tool
LIB_TARGET = $(LIB_DIR)/libkey-tool.so

INSTALL_BIN_DIR = /usr/local/bin
INSTALL_LIB_DIR = /usr/local/lib
INSTALL_INCLUDE_DIR = /usr/local/include/key_tool

.PHONY: all clean install libdir lib

all: $(BIN_DIR) $(TARGET)

lib: libdir $(LIB_TARGET)

libdir:
	mkdir -p $(LIB_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

$(LIB_TARGET): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -fPIC -shared $(SRC) -o $@ $(LDFLAGS)

install: all lib
	mkdir -p $(INSTALL_BIN_DIR)
	mkdir -p $(INSTALL_LIB_DIR)
	mkdir -p $(INSTALL_INCLUDE_DIR)
	install -m 755 $(TARGET) $(INSTALL_BIN_DIR)/
	install -m 644 $(LIB_TARGET) $(INSTALL_LIB_DIR)/
	install -m 644 $(HEADERS) $(INSTALL_INCLUDE_DIR)/
	ldconfig

clean:
	rm -rf $(BIN_DIR) $(LIB_DIR)
