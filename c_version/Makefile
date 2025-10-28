# Makefile for Sindarin C Implementation

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -I.
LDFLAGS =

# Source files
SOURCES = sindarin.c monocypher.c
HEADERS = sindarin.h monocypher.h
TEST_SOURCES = test_sindarin.c

# Object files
OBJECTS = sindarin.o monocypher.o
TEST_OBJECTS = test_sindarin.o

# Targets
LIB = libsindarin.a
TEST_BIN = test_sindarin

.PHONY: all clean test

all: $(LIB) $(TEST_BIN)

# Build static library
$(LIB): $(OBJECTS)
	ar rcs $@ $^

# Build test binary
$(TEST_BIN): $(TEST_OBJECTS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJECTS) -L. -lsindarin $(LDFLAGS)

# Compile source files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Run tests
test: $(TEST_BIN)
	./$(TEST_BIN)

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS) $(LIB) $(TEST_BIN) monocypher.o

# Install library (optional)
install: $(LIB)
	mkdir -p /usr/local/lib
	mkdir -p /usr/local/include
	cp $(LIB) /usr/local/lib/
	cp $(HEADERS) /usr/local/include/

# Uninstall library (optional)
uninstall:
	rm -f /usr/local/lib/$(LIB)
	rm -f /usr/local/include/sindarin.h

# Help target
help:
	@echo "Sindarin C Implementation Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Build library and tests (default)"
	@echo "  $(LIB)    - Build static library"
	@echo "  $(TEST_BIN) - Build test binary"
	@echo "  test      - Run tests"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install library to /usr/local"
	@echo "  uninstall - Remove library from /usr/local"
	@echo "  help      - Show this help message"
