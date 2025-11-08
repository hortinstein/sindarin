# C Implementation - Sindarin Encryption & Serialization

This directory contains a C implementation of the encryption and serialization system that is fully interoperable with the Python and Nim versions.

## Features

- ✅ **Monocypher encryption** - Compatible X25519 key exchange and ChaCha20-Poly1305 encryption
- ✅ **Flatty serialization** - Binary-compatible with Nim's Flatty library
- ✅ **Full type support** - All data types from Nim (EncObj, StaticConfig, Status, Task, etc.)
- ✅ **Interoperability** - Can encrypt/decrypt and serialize/deserialize data created by Python or Nim
- ✅ **Memory safe** - Proper cleanup and error handling

## Building

```bash
make all
```

This will:
- Download Monocypher library
- Compile all source files
- Create `libsindarin.a` static library
- Build all test programs

## Running Tests

### C Standalone Tests

Test C encryption functionality:
```bash
./test_encryption
```

Test C serialization functionality:
```bash
./test_serialization
```

Test full roundtrip (encrypt → serialize → deserialize → decrypt):
```bash
./test_roundtrip
```

Run all C tests:
```bash
make run_tests
```

### Interoperability Tests

Create C data for Python to read:
```bash
./test_c_to_python
```

Read Python data in C:
```bash
./test_python_to_c
```

Run full interoperability test suite:
```bash
cd ..
./test_c_interop.sh
```

## File Structure

### Core Implementation
- `types.h` / `types.c` - Data structure definitions matching Nim/Python types
- `flatty.h` / `flatty.c` - Flatty serialization/deserialization
- `enkodo.h` / `enkodo.c` - Encryption/decryption using Monocypher
- `monocypher.h` / `monocypher.c` - Monocypher cryptography library

### Test Programs
- `test_encryption.c` - Tests encryption/decryption functionality
- `test_serialization.c` - Tests serialization/deserialization
- `test_roundtrip.c` - Tests complete encrypt+serialize+deserialize+decrypt flow
- `test_c_to_python.c` - Creates data files for Python to read
- `test_python_to_c.c` - Reads data files created by Python

### Build System
- `Makefile` - Build configuration
- `libsindarin.a` - Compiled static library (created by make)

## Data Types Supported

All types match the Nim and Python implementations:

### Fixed-size Types
- `Key` - 32-byte encryption key
- `Nonce` - 24-byte nonce
- `Mac` - 16-byte MAC

### Encryption Types
- `EncObj` - Encrypted object with public key, nonce, MAC, and ciphertext
- `EncConfig` - Encrypted configuration with key pair

### Configuration Types
- `StaticConfig` - Agent configuration (buildID, deploymentID, c2PubKey, etc.)
- `Status` - System status information
- `Callback` - Combined config and status
- `Task` - Task definition
- `Resp` - Response object

## API Examples

### Key Generation
```c
Key priv, pub;
generate_key_pair(&priv, &pub);
```

### Encryption
```c
EncObj enc_obj;
const char* message = "Hello, World!";
enc(&sender_priv, &recipient_pub,
    (uint8_t*)message, strlen(message), &enc_obj);
```

### Decryption
```c
uint8_t* plaintext;
size_t plaintext_len;
dec(&recipient_priv, &enc_obj, &plaintext, &plaintext_len);
```

### Serialization
```c
size_t buffer_size = calc_enc_obj_size(&enc_obj);
uint8_t* buffer = malloc(buffer_size);
serialize_enc_obj(&enc_obj, buffer);
```

### Deserialization
```c
EncObj enc_obj;
deserialize_enc_obj(buffer, buffer_len, &enc_obj);
```

## Memory Management

All `deserialize_*` functions allocate memory that must be freed. Use the provided cleanup functions:

```c
free_enc_obj(&enc_obj);
free_static_config(&config);
free_status(&status);
free_task(&task);
// etc.
```

## Interoperability Details

### Binary Compatibility

The C implementation uses the exact same binary format as Nim's Flatty library:

- **Strings**: 8-byte little-endian length prefix + UTF-8 data
- **Integers**: Little-endian encoding (int32 = 4 bytes, int64 = 8 bytes)
- **Booleans**: Single byte (0 = false, 1 = true)
- **Ref objects**: Single byte nil flag (0 = not nil, 1 = nil) followed by data
- **Sequences**: 8-byte little-endian length + data

### Encryption Compatibility

Uses Monocypher which is compatible with:
- Nim's monocypher library
- Python's pymonocypher library

Both use X25519 key exchange and ChaCha20-Poly1305 AEAD.

## Cleaning Up

```bash
make clean
```

This removes all compiled binaries, object files, and test data files.

## Dependencies

- GCC or compatible C compiler
- C11 standard library
- Monocypher (automatically downloaded by Makefile)

## Security Notes

- Keys are wiped from memory after use using `crypto_wipe()`
- Random number generation uses `/dev/urandom` on Unix or `CryptGenRandom` on Windows
- MAC verification ensures message authenticity
- All encryption uses authenticated encryption (AEAD)
