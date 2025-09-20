CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -fPIC -D_GNU_SOURCE
INCLUDES = -I.
LIBS = 

SRCDIR = .
OBJDIR = obj
BINDIR = bin

# Core source files (excluding test files)
CORE_SOURCES = types.c flatty.c enkodo.c monocypher.c
CORE_OBJECTS = $(CORE_SOURCES:%.c=$(OBJDIR)/%.o)
HEADERS = $(wildcard $(SRCDIR)/*.h)

TARGETS = $(BINDIR)/test_interop $(BINDIR)/config_reader $(BINDIR)/config_generator

all: $(TARGETS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS) | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BINDIR)/test_interop: $(CORE_OBJECTS) $(OBJDIR)/test_interop.o | $(BINDIR)
	$(CC) $^ -o $@ $(LIBS)

$(BINDIR)/config_reader: $(CORE_OBJECTS) $(OBJDIR)/config_reader.o | $(BINDIR)
	$(CC) $^ -o $@ $(LIBS)

$(BINDIR)/config_generator: $(CORE_OBJECTS) $(OBJDIR)/config_generator.o | $(BINDIR)
	$(CC) $^ -o $@ $(LIBS)

libsindarin.so: $(CORE_OBJECTS)
	$(CC) -shared $^ -o $@ $(LIBS)

libsindarin.a: $(CORE_OBJECTS)
	ar rcs $@ $^

clean:
	rm -rf $(OBJDIR) $(BINDIR) libsindarin.so libsindarin.a

test: $(BINDIR)/test_interop
	./$(BINDIR)/test_interop

.PHONY: all clean test

# Download monocypher if needed
monocypher.h:
	wget -q https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src/monocypher.h

monocypher.c:
	wget -q https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src/monocypher.c

download-monocypher: monocypher.h monocypher.c