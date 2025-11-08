CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -g
LDFLAGS =

# Source files
SRCS = types.c flatty.c enkodo.c monocypher.c
OBJS = $(SRCS:.c=.o)

# Test programs
TEST_PROGS = test_encryption test_serialization test_c_to_python test_python_to_c test_roundtrip

# Library
LIB = libsindarin.a

.PHONY: all clean tests run_tests

all: $(LIB) $(TEST_PROGS)

$(LIB): $(OBJS)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test_encryption: test_encryption.c $(LIB)
	$(CC) $(CFLAGS) $< -L. -lsindarin -o $@ $(LDFLAGS)

test_serialization: test_serialization.c $(LIB)
	$(CC) $(CFLAGS) $< -L. -lsindarin -o $@ $(LDFLAGS)

test_c_to_python: test_c_to_python.c $(LIB)
	$(CC) $(CFLAGS) $< -L. -lsindarin -o $@ $(LDFLAGS)

test_python_to_c: test_python_to_c.c $(LIB)
	$(CC) $(CFLAGS) $< -L. -lsindarin -o $@ $(LDFLAGS)

test_roundtrip: test_roundtrip.c $(LIB)
	$(CC) $(CFLAGS) $< -L. -lsindarin -o $@ $(LDFLAGS)

tests: $(TEST_PROGS)

run_tests: tests
	@echo "Running C encryption tests..."
	./test_encryption
	@echo "\nRunning C serialization tests..."
	./test_serialization
	@echo "\nAll C tests passed!"

clean:
	rm -f $(OBJS) $(LIB) $(TEST_PROGS)
	rm -f *.bin *.enc *.config test_*.dat

# Dependencies
types.o: types.c types.h
flatty.o: flatty.c flatty.h types.h
enkodo.o: enkodo.c enkodo.h types.h flatty.h monocypher.h
monocypher.o: monocypher.c monocypher.h
