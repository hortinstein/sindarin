# Sindarin C Implementation

A C library implementing binary-compatible serialization and encryption with the Nim/Python Sindarin project.

## Features

- **Flatty Serialization**: Binary-compatible implementation of Nim's Flatty serialization format
- **Monocypher Encryption**: X25519 key exchange and authenticated encryption
- **Cross-platform**: Compatible with Nim and Python implementations
- **Type Support**: Full support for all Sindarin data types:
  - `EncConfig` - Encrypted configuration
  - `StaticConfig` - Static configuration
  - `Status` - System status information
  - `Callback` - Callback with config and status
  - `Task` - Task definition
  - `Resp` - Response object

## Dependencies

- **Monocypher**: Cryptographic library
  - Install on Ubuntu/Debian: `sudo apt-get install libmonocypher-dev`
  - Install on macOS: `brew install monocypher`
  - Or build from source: https://monocypher.org/

## Building

```bash
# Build library and tests
make

# Build only the library
make libsindarin.a

# Build only the tests
make test_sindarin

# Run tests
make test

# Clean build artifacts
make clean
```

## Installation

```bash
# Install library to /usr/local
sudo make install

# Uninstall
sudo make uninstall
```

## Usage

### Include Header

```c
#include <sindarin.h>
```

### Generate Key Pair

```c
Key priv_key, pub_key;
generate_key_pair(&priv_key, &pub_key);
```

### Encrypt a Message

```c
const char* message = "Hello, World!";
size_t msg_len = strlen(message);

EncObj* enc_obj = encrypt_message(&sender_priv, &recipient_pub,
                                   (uint8_t*)message, msg_len);
```

### Decrypt a Message

```c
size_t decrypted_len;
uint8_t* decrypted = decrypt_message(&recipient_priv, enc_obj, &decrypted_len);
if (decrypted != NULL) {
    // Use decrypted message
    free(decrypted);
}
```

### Serialize a StaticConfig

```c
StaticConfig config;
config.buildID = "build-001";
config.deploymentID = "deploy-001";
config.killEpoch = 1234567890;
config.interval = 60;
config.callback = "https://c2.example.com/callback";

size_t ser_len;
uint8_t* serialized = serialize_static_config(&config, &ser_len);

// Use serialized data...

free(serialized);
```

### Deserialize a StaticConfig

```c
size_t offset = 0;
StaticConfig* config = deserialize_static_config(serialized, ser_len, &offset);

if (config != NULL) {
    printf("Build ID: %s\n", config->buildID);
    free_static_config(config);
}
```

## Binary Compatibility

This C implementation uses the same Flatty serialization format as the Nim and Python versions:

- **Strings**: 8-byte length prefix (little-endian) + UTF-8 data
- **Integers**: Little-endian encoding (int32 = 4 bytes, int64 = 8 bytes)
- **Booleans**: Single byte (0 = false, 1 = true)
- **Fixed-size types**: Raw bytes (Key = 32, Nonce = 24, Mac = 16)
- **Ref objects**: Preceded by nil indicator byte (0 = not nil, 1 = nil)
- **Sequences**: 8-byte length prefix + elements

## Memory Management

All deserialization functions allocate memory that must be freed:

```c
// Free individual objects
free_enc_obj(enc_obj);
free_enc_config(enc_config);
free_static_config(config);
free_status(status);
free_callback(callback);
free_task(task);
free_resp(resp);

// Free serialized data
free(serialized_data);
```

## Examples

See `test_sindarin.c` for comprehensive examples of:
- Encryption/decryption
- Serialization/deserialization
- Creating and manipulating all data types
- Binary compatibility testing

## Testing

Run the test suite:

```bash
make test
```

To test compatibility with Nim-generated data:

```bash
# Generate debug.config using Nim
cd ../nim_config && nimble run

# Run C tests
cd ../c_version && make test
```

## API Reference

### Encryption Functions

- `void generate_key_pair(Key* priv_key, Key* pub_key)` - Generate X25519 key pair
- `EncObj* encrypt_message(...)` - Encrypt message with authenticated encryption
- `uint8_t* decrypt_message(...)` - Decrypt and verify message

### Serialization Functions

Each type has corresponding serialize/deserialize functions:

- `uint8_t* serialize_<type>(<Type>* obj, size_t* out_len)`
- `<Type>* deserialize_<type>(const uint8_t* data, size_t len, ...)`

### Memory Management Functions

- `void free_<type>(<Type>* obj)` - Free allocated object

## Architecture

```
sindarin.h          - Type definitions and function declarations
sindarin.c          - Implementation of serialization and encryption
test_sindarin.c     - Test suite
Makefile           - Build configuration
```

## License

This project is part of the Sindarin educational project demonstrating binary compatibility between Nim, Python, and C using the Flatty serialization format and Monocypher cryptography.

## Contributing

When contributing, ensure:
1. Binary compatibility with Nim/Python versions
2. Proper memory management (no leaks)
3. Tests pass with `make test`
4. Code follows C11 standard

## Troubleshooting

### Monocypher not found

```bash
# Ubuntu/Debian
sudo apt-get install libmonocypher-dev

# macOS
brew install monocypher

# Or specify library path
make LDFLAGS="-L/path/to/monocypher -lmonocypher"
```

### Tests fail

Ensure you have generated test data:
```bash
cd ../nim_config && nimble run
```

### Linking errors

Try building with explicit library path:
```bash
gcc -o test_sindarin test_sindarin.c sindarin.c -I. -L/usr/local/lib -lmonocypher
```
